#include <ntddk.h>
#include <ntddmou.h>
#include <ntstrsafe.h>

//
// Pure WDM Virtual Mouse Driver - Mapper Compatible
// Uses direct mouclass callback injection for real mouse input
// FULLY RELOCATABLE - No global strings or static data dependencies
//

#pragma warning(disable: 4201)

// ============================================================================
// Configuration
// ============================================================================

#define VHID_DEVICE_TYPE        0x8000
#define VHID_POOL_TAG           'dihV'

#define IOCTL_VHID_MOUSE_MOVE \
    CTL_CODE(VHID_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_VHID_SECURE_INPUT \
    CTL_CODE(VHID_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VHID_ENCRYPTION_KEY     0xAB

// ============================================================================
// Structures
// ============================================================================

typedef struct _MOUSE_MOVE_REQUEST {
    LONG dx;
    LONG dy;
    UCHAR buttons;
    UCHAR wheel;
} MOUSE_MOVE_REQUEST, *PMOUSE_MOVE_REQUEST;

typedef enum _VHID_PACKET_TYPE {
    PacketType_Mouse = 1,
    PacketType_Keyboard = 2
} VHID_PACKET_TYPE;

typedef struct _VHID_SECURE_PACKET {
    UCHAR Type;
    UCHAR Size;
    UCHAR Payload[16];
} VHID_SECURE_PACKET, *PVHID_SECURE_PACKET;

// Mouse class callback signature
typedef VOID (*MOUSE_SERVICE_CALLBACK)(
    PDEVICE_OBJECT DeviceObject,
    PMOUSE_INPUT_DATA InputDataStart,
    PMOUSE_INPUT_DATA InputDataEnd,
    PULONG InputDataConsumed
);

// Mouse class device extension structure (partial, from reverse engineering)
typedef struct _MOUSE_CLASS_DATA {
    ULONG Reserved1;
    PDEVICE_OBJECT Self;
    ULONG Reserved2[10];
    MOUSE_SERVICE_CALLBACK ServiceCallback;
    // ... more fields we don't need
} MOUSE_CLASS_DATA, *PMOUSE_CLASS_DATA;

// Our device extension - ALL STATE STORED HERE (no globals!)
typedef struct _VHID_EXTENSION {
    PDEVICE_OBJECT Self;
    PDEVICE_OBJECT MouseDevice;
    MOUSE_SERVICE_CALLBACK MouseCallback;
    KSPIN_LOCK Lock;
    UCHAR LastButtons;
    
    // Store device name strings in extension (relocatable)
    WCHAR DeviceNameBuffer[64];
    WCHAR SymbolicLinkBuffer[64];
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLink;
    BOOLEAN SymbolicLinkCreated;
} VHID_EXTENSION, *PVHID_EXTENSION;

// ============================================================================
// Globals - Minimized for mapper compatibility
// Only a single pointer that gets set during DriverEntry
// ============================================================================

static PDEVICE_OBJECT g_Device = NULL;

// ============================================================================
// External Imports
// ============================================================================

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);

NTKERNELAPI POBJECT_TYPE *IoDriverObjectType;

// ============================================================================
// Function Declarations
// ============================================================================

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH VhidCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH VhidDeviceControl;

// ============================================================================
// Mouse Injection via MouClass Callback
// ============================================================================

static NTSTATUS FindMouseCallback(PVHID_EXTENSION Ext)
{
    NTSTATUS status;
    UNICODE_STRING driverName;
    PDRIVER_OBJECT mouseDriver = NULL;
    PDEVICE_OBJECT deviceObject;
    WCHAR driverNameBuf[32];
    WCHAR* p;
    
    // Build driver name dynamically (relocatable)
    // \Driver\MouClass
    p = driverNameBuf;
    *p++ = L'\\'; *p++ = L'D'; *p++ = L'r'; *p++ = L'i'; *p++ = L'v';
    *p++ = L'e'; *p++ = L'r'; *p++ = L'\\'; *p++ = L'M'; *p++ = L'o';
    *p++ = L'u'; *p++ = L'C'; *p++ = L'l'; *p++ = L'a'; *p++ = L's';
    *p++ = L's'; *p = L'\0';
    
    driverName.Buffer = driverNameBuf;
    driverName.Length = 16 * sizeof(WCHAR);
    driverName.MaximumLength = sizeof(driverNameBuf);
    
    status = ObReferenceObjectByName(
        &driverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&mouseDriver
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Walk device list to find one with a callback
    deviceObject = mouseDriver->DeviceObject;
    while (deviceObject != NULL) {
        // The callback is stored at DeviceExtension + offset
        // This offset varies by Windows version, try common ones
        PVOID devExt = deviceObject->DeviceExtension;
        if (devExt != NULL) {
            // Try to find ServiceCallback in device extension
            // Common offsets: 0x28, 0x30, 0x38, 0x40
            PULONG_PTR pCallback;
            ULONG offsets[] = { 0x28, 0x30, 0x38, 0x40, 0x48, 0x50 };
            ULONG i;
            
            for (i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
                pCallback = (PULONG_PTR)((PUCHAR)devExt + offsets[i]);
                
                // Validate it looks like a kernel function pointer
                if (*pCallback > 0xFFFF800000000000ULL && 
                    *pCallback < 0xFFFFFFFFFFFFFFF0ULL) {
                    // Found a potential callback
                    Ext->MouseDevice = deviceObject;
                    Ext->MouseCallback = (MOUSE_SERVICE_CALLBACK)*pCallback;
                    ObDereferenceObject(mouseDriver);
                    return STATUS_SUCCESS;
                }
            }
        }
        deviceObject = deviceObject->NextDevice;
    }
    
    ObDereferenceObject(mouseDriver);
    return STATUS_NOT_FOUND;
}

static NTSTATUS InjectMouse(PVHID_EXTENSION Ext, PMOUSE_MOVE_REQUEST Move)
{
    MOUSE_INPUT_DATA inputData = {0};
    ULONG consumed = 0;
    KIRQL irql;
    
    if (Ext->MouseCallback == NULL || Ext->MouseDevice == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    
    // Build mouse input data
    inputData.UnitId = 0;
    inputData.Flags = MOUSE_MOVE_RELATIVE;
    inputData.LastX = Move->dx;
    inputData.LastY = Move->dy;
    
    // Handle button state changes
    KeAcquireSpinLock(&Ext->Lock, &irql);
    
    // Left button
    if ((Move->buttons & 0x01) && !(Ext->LastButtons & 0x01)) {
        inputData.ButtonFlags |= MOUSE_LEFT_BUTTON_DOWN;
    } else if (!(Move->buttons & 0x01) && (Ext->LastButtons & 0x01)) {
        inputData.ButtonFlags |= MOUSE_LEFT_BUTTON_UP;
    }
    
    // Right button
    if ((Move->buttons & 0x02) && !(Ext->LastButtons & 0x02)) {
        inputData.ButtonFlags |= MOUSE_RIGHT_BUTTON_DOWN;
    } else if (!(Move->buttons & 0x02) && (Ext->LastButtons & 0x02)) {
        inputData.ButtonFlags |= MOUSE_RIGHT_BUTTON_UP;
    }
    
    // Middle button
    if ((Move->buttons & 0x04) && !(Ext->LastButtons & 0x04)) {
        inputData.ButtonFlags |= MOUSE_MIDDLE_BUTTON_DOWN;
    } else if (!(Move->buttons & 0x04) && (Ext->LastButtons & 0x04)) {
        inputData.ButtonFlags |= MOUSE_MIDDLE_BUTTON_UP;
    }
    
    // X1 button
    if ((Move->buttons & 0x08) && !(Ext->LastButtons & 0x08)) {
        inputData.ButtonFlags |= MOUSE_BUTTON_4_DOWN;
    } else if (!(Move->buttons & 0x08) && (Ext->LastButtons & 0x08)) {
        inputData.ButtonFlags |= MOUSE_BUTTON_4_UP;
    }
    
    // X2 button
    if ((Move->buttons & 0x10) && !(Ext->LastButtons & 0x10)) {
        inputData.ButtonFlags |= MOUSE_BUTTON_5_DOWN;
    } else if (!(Move->buttons & 0x10) && (Ext->LastButtons & 0x10)) {
        inputData.ButtonFlags |= MOUSE_BUTTON_5_UP;
    }
    
    Ext->LastButtons = Move->buttons;
    KeReleaseSpinLock(&Ext->Lock, irql);
    
    // Wheel
    if (Move->wheel != 0) {
        inputData.ButtonFlags |= MOUSE_WHEEL;
        inputData.ButtonData = (SHORT)((CHAR)Move->wheel) * 120;
    }
    
    // Call the mouclass callback
    __try {
        Ext->MouseCallback(
            Ext->MouseDevice,
            &inputData,
            &inputData + 1,
            &consumed
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Helper: Build device name strings dynamically (relocatable)
// ============================================================================

static VOID BuildDeviceStrings(PVHID_EXTENSION Ext)
{
    // Build device name: \Device\VHIDMouse
    // Using character-by-character assignment to avoid string literal relocation issues
    WCHAR* p = Ext->DeviceNameBuffer;
    *p++ = L'\\'; *p++ = L'D'; *p++ = L'e'; *p++ = L'v'; *p++ = L'i'; 
    *p++ = L'c'; *p++ = L'e'; *p++ = L'\\'; *p++ = L'V'; *p++ = L'H'; 
    *p++ = L'I'; *p++ = L'D'; *p++ = L'M'; *p++ = L'o'; *p++ = L'u'; 
    *p++ = L's'; *p++ = L'e'; *p = L'\0';
    
    Ext->DeviceName.Buffer = Ext->DeviceNameBuffer;
    Ext->DeviceName.Length = 17 * sizeof(WCHAR);
    Ext->DeviceName.MaximumLength = sizeof(Ext->DeviceNameBuffer);
    
    // Build symbolic link: \DosDevices\VHIDMouse
    p = Ext->SymbolicLinkBuffer;
    *p++ = L'\\'; *p++ = L'D'; *p++ = L'o'; *p++ = L's'; *p++ = L'D'; 
    *p++ = L'e'; *p++ = L'v'; *p++ = L'i'; *p++ = L'c'; *p++ = L'e'; 
    *p++ = L's'; *p++ = L'\\'; *p++ = L'V'; *p++ = L'H'; *p++ = L'I'; 
    *p++ = L'D'; *p++ = L'M'; *p++ = L'o'; *p++ = L'u'; *p++ = L's'; 
    *p++ = L'e'; *p = L'\0';
    
    Ext->SymbolicLink.Buffer = Ext->SymbolicLinkBuffer;
    Ext->SymbolicLink.Length = 21 * sizeof(WCHAR);
    Ext->SymbolicLink.MaximumLength = sizeof(Ext->SymbolicLinkBuffer);
}

// ============================================================================
// Device Creation / Destruction
// ============================================================================

static NTSTATUS CreateVhidDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    PVHID_EXTENSION ext;
    UNICODE_STRING tempDevName;
    WCHAR tempDevNameBuf[64];
    WCHAR* p;
    
    // Build temporary device name on stack for IoCreateDevice
    p = tempDevNameBuf;
    *p++ = L'\\'; *p++ = L'D'; *p++ = L'e'; *p++ = L'v'; *p++ = L'i'; 
    *p++ = L'c'; *p++ = L'e'; *p++ = L'\\'; *p++ = L'V'; *p++ = L'H'; 
    *p++ = L'I'; *p++ = L'D'; *p++ = L'M'; *p++ = L'o'; *p++ = L'u'; 
    *p++ = L's'; *p++ = L'e'; *p = L'\0';
    
    tempDevName.Buffer = tempDevNameBuf;
    tempDevName.Length = 17 * sizeof(WCHAR);
    tempDevName.MaximumLength = sizeof(tempDevNameBuf);
    
    status = IoCreateDevice(
        DriverObject,
        sizeof(VHID_EXTENSION),
        &tempDevName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    ext = (PVHID_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(ext, sizeof(VHID_EXTENSION));
    ext->Self = deviceObject;
    KeInitializeSpinLock(&ext->Lock);
    
    // Build device strings in extension (relocatable)
    BuildDeviceStrings(ext);
    
    status = IoCreateSymbolicLink(&ext->SymbolicLink, &ext->DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    ext->SymbolicLinkCreated = TRUE;
    
    // Find mouclass callback
    status = FindMouseCallback(ext);
    if (!NT_SUCCESS(status)) {
        // Log but continue - callback might be found later
    }
    
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    g_Device = deviceObject;
    return STATUS_SUCCESS;
}

static VOID DestroyVhidDevice(VOID)
{
    PVHID_EXTENSION ext;
    
    if (g_Device == NULL) return;
    
    ext = (PVHID_EXTENSION)g_Device->DeviceExtension;
    
    // Use extension-based symbolic link (relocatable)
    if (ext->SymbolicLinkCreated) {
        IoDeleteSymbolicLink(&ext->SymbolicLink);
    }
    
    IoDeleteDevice(g_Device);
    g_Device = NULL;
}

// ============================================================================
// IRP Handlers
// ============================================================================

NTSTATUS VhidCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PVHID_EXTENSION ext = (PVHID_EXTENSION)DeviceObject->DeviceExtension;
    
    // Re-try finding callback on open if not found yet
    if (ext->MouseCallback == NULL) {
        FindMouseCallback(ext);
    }
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS VhidDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PVHID_EXTENSION ext = (PVHID_EXTENSION)DeviceObject->DeviceExtension;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    
    switch (code) {
        
    case IOCTL_VHID_MOUSE_MOVE:
        if (inLen < sizeof(MOUSE_MOVE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = InjectMouse(ext, (PMOUSE_MOVE_REQUEST)buffer);
        }
        break;
        
    case IOCTL_VHID_SECURE_INPUT:
        if (inLen < sizeof(VHID_SECURE_PACKET)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PVHID_SECURE_PACKET pkt = (PVHID_SECURE_PACKET)buffer;
            UCHAR* raw = (UCHAR*)pkt;
            ULONG i;
            
            for (i = 0; i < sizeof(VHID_SECURE_PACKET); i++) {
                raw[i] ^= VHID_ENCRYPTION_KEY;
            }
            
            if (pkt->Type == PacketType_Mouse && pkt->Size == sizeof(MOUSE_MOVE_REQUEST)) {
                status = InjectMouse(ext, (PMOUSE_MOVE_REQUEST)pkt->Payload);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        break;
        
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ============================================================================
// Driver Entry / Unload
// ============================================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DestroyVhidDevice();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    if (DriverObject != NULL) {
        DriverObject->DriverUnload = DriverUnload;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = VhidCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = VhidCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VhidDeviceControl;
    }
    
    return CreateVhidDevice(DriverObject);
}
