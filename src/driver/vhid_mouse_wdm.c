#include <ntddk.h>
#include <ntddmou.h>
#include <ntstrsafe.h>

//
// Pure WDM Virtual HID Mouse Driver - No WDF Dependencies
// Designed for manual mapping via kernel driver mapper
//

#pragma warning(disable: 4201) // nameless struct/union

// ============================================================================
// Constants and Configuration
// ============================================================================

#define VHID_DEVICE_TYPE        0x8000
#define VHID_POOL_TAG           'dihV'

#define IOCTL_VHID_MOUSE_MOVE \
    CTL_CODE(VHID_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_VHID_SECURE_INPUT \
    CTL_CODE(VHID_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define VHID_ENCRYPTION_KEY     0xAB

// ============================================================================
// Data Structures
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

// Device extension - all state stored here (in NonPaged pool)
typedef struct _VHID_DEVICE_EXTENSION {
    PDEVICE_OBJECT Self;
    PDEVICE_OBJECT MouseClassDevice;    // Attached mouclass device
    UNICODE_STRING SymbolicLink;
    BOOLEAN SymbolicLinkCreated;
    
    // Mouse state
    KSPIN_LOCK StateLock;
    MOUSE_INPUT_DATA LastInputData;
    
    // For direct mouse injection
    PVOID MouseClassCallback;           // MouseClassServiceCallback
    PDEVICE_OBJECT MouseClassDeviceObject;
} VHID_DEVICE_EXTENSION, *PVHID_DEVICE_EXTENSION;

// ============================================================================
// Globals (minimized for mapper compatibility)
// ============================================================================

static PDEVICE_OBJECT g_DeviceObject = NULL;
static PDRIVER_OBJECT g_DriverObject = NULL;

// Device name stored on stack to avoid .data section issues
#define DEVICE_NAME_BUFFER      L"\\Device\\VHIDMouse"
#define SYMLINK_NAME_BUFFER     L"\\DosDevices\\VHIDMouse"

// ============================================================================
// Forward Declarations
// ============================================================================

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DispatchCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DispatchDeviceControl;

static NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject);
static VOID DestroyDevice(VOID);
static NTSTATUS FindMouseClassDevice(PVHID_DEVICE_EXTENSION DevExt);
static NTSTATUS InjectMouseInput(PVHID_DEVICE_EXTENSION DevExt, PMOUSE_MOVE_REQUEST MoveData);

// ============================================================================
// Mouse Class Callback Type (from mouclass)
// ============================================================================

typedef VOID (*MOUSE_CLASS_SERVICE_CALLBACK)(
    PDEVICE_OBJECT DeviceObject,
    PMOUSE_INPUT_DATA InputDataStart,
    PMOUSE_INPUT_DATA InputDataEnd,
    PULONG InputDataConsumed
);

// ============================================================================
// Driver Entry Point
// ============================================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    // For mapped drivers, DriverObject might be NULL or a fake object
    // We need to handle both cases
    
    if (DriverObject != NULL) {
        g_DriverObject = DriverObject;
        
        DriverObject->DriverUnload = DriverUnload;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    }
    
    // Create our device
    status = CreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Driver Unload
// ============================================================================

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DestroyDevice();
}

// ============================================================================
// Device Creation
// ============================================================================

static NTSTATUS CreateDevice(
    PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    PDEVICE_OBJECT deviceObject = NULL;
    PVHID_DEVICE_EXTENSION devExt = NULL;
    
    // Initialize strings on stack
    RtlInitUnicodeString(&deviceName, DEVICE_NAME_BUFFER);
    RtlInitUnicodeString(&symbolicLink, SYMLINK_NAME_BUFFER);
    
    // Create device object
    status = IoCreateDevice(
        DriverObject,
        sizeof(VHID_DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Initialize device extension
    devExt = (PVHID_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(devExt, sizeof(VHID_DEVICE_EXTENSION));
    
    devExt->Self = deviceObject;
    KeInitializeSpinLock(&devExt->StateLock);
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    devExt->SymbolicLinkCreated = TRUE;
    RtlInitUnicodeString(&devExt->SymbolicLink, SYMLINK_NAME_BUFFER);
    
    // Find mouse class device for input injection
    status = FindMouseClassDevice(devExt);
    if (!NT_SUCCESS(status)) {
        // Non-fatal - we can still receive IOCTLs but can't inject
    }
    
    // Set up buffered I/O
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    g_DeviceObject = deviceObject;
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Device Destruction
// ============================================================================

static VOID DestroyDevice(VOID)
{
    PVHID_DEVICE_EXTENSION devExt;
    UNICODE_STRING symbolicLink;
    
    if (g_DeviceObject == NULL) {
        return;
    }
    
    devExt = (PVHID_DEVICE_EXTENSION)g_DeviceObject->DeviceExtension;
    
    if (devExt->SymbolicLinkCreated) {
        RtlInitUnicodeString(&symbolicLink, SYMLINK_NAME_BUFFER);
        IoDeleteSymbolicLink(&symbolicLink);
    }
    
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
}

// ============================================================================
// Find Mouse Class Device
// ============================================================================

static NTSTATUS FindMouseClassDevice(
    PVHID_DEVICE_EXTENSION DevExt
)
{
    NTSTATUS status;
    UNICODE_STRING mouseClassName;
    PDRIVER_OBJECT mouseDriver = NULL;
    PDEVICE_OBJECT mouseDevice = NULL;
    
    // Try to find mouclass driver
    RtlInitUnicodeString(&mouseClassName, L"\\Driver\\MouClass");
    
    status = ObReferenceObjectByName(
        &mouseClassName,
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
    
    // Get the first device object
    mouseDevice = mouseDriver->DeviceObject;
    if (mouseDevice != NULL) {
        DevExt->MouseClassDeviceObject = mouseDevice;
        
        // Try to find MouseClassServiceCallback in the driver
        // This is typically at a known offset in mouclass
        // For now, we'll use a different injection method
    }
    
    ObDereferenceObject(mouseDriver);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Mouse Input Injection
// ============================================================================

static NTSTATUS InjectMouseInput(
    PVHID_DEVICE_EXTENSION DevExt,
    PMOUSE_MOVE_REQUEST MoveData
)
{
    MOUSE_INPUT_DATA inputData;
    KIRQL oldIrql;
    
    UNREFERENCED_PARAMETER(DevExt);
    
    // Build MOUSE_INPUT_DATA structure
    RtlZeroMemory(&inputData, sizeof(inputData));
    
    inputData.UnitId = 0;
    inputData.LastX = MoveData->dx;
    inputData.LastY = MoveData->dy;
    inputData.Flags = MOUSE_MOVE_RELATIVE;
    
    // Handle buttons
    if (MoveData->buttons & 0x01) {
        inputData.ButtonFlags |= MOUSE_LEFT_BUTTON_DOWN;
    }
    if (MoveData->buttons & 0x02) {
        inputData.ButtonFlags |= MOUSE_RIGHT_BUTTON_DOWN;
    }
    if (MoveData->buttons & 0x04) {
        inputData.ButtonFlags |= MOUSE_MIDDLE_BUTTON_DOWN;
    }
    
    // Handle wheel
    if (MoveData->wheel != 0) {
        inputData.ButtonFlags |= MOUSE_WHEEL;
        inputData.ButtonData = (SHORT)((CHAR)MoveData->wheel) * 120;
    }
    
    // Store for potential retrieval
    KeAcquireSpinLock(&DevExt->StateLock, &oldIrql);
    RtlCopyMemory(&DevExt->LastInputData, &inputData, sizeof(inputData));
    KeReleaseSpinLock(&DevExt->StateLock, oldIrql);
    
    // For actual injection, we need to call mouclass callback
    // This requires finding MouseClassServiceCallback
    // Alternative: Use MouHid path or SendInput from usermode
    
    return STATUS_SUCCESS;
}

// ============================================================================
// IRP Dispatch - Create/Close
// ============================================================================

NTSTATUS DispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// IRP Dispatch - Device Control
// ============================================================================

NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;
    PVHID_DEVICE_EXTENSION devExt;
    PVOID inputBuffer;
    ULONG inputLength;
    ULONG ioControlCode;
    ULONG_PTR information = 0;
    
    irpSp = IoGetCurrentIrpStackLocation(Irp);
    devExt = (PVHID_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioControlCode) {
        
    case IOCTL_VHID_MOUSE_MOVE:
        if (inputLength < sizeof(MOUSE_MOVE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        
        status = InjectMouseInput(devExt, (PMOUSE_MOVE_REQUEST)inputBuffer);
        break;
        
    case IOCTL_VHID_SECURE_INPUT:
        if (inputLength < sizeof(VHID_SECURE_PACKET)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        
        {
            PVHID_SECURE_PACKET packet = (PVHID_SECURE_PACKET)inputBuffer;
            UCHAR* raw = (UCHAR*)packet;
            ULONG i;
            
            // Decrypt (XOR)
            for (i = 0; i < sizeof(VHID_SECURE_PACKET); i++) {
                raw[i] ^= VHID_ENCRYPTION_KEY;
            }
            
            // Process based on type
            if (packet->Type == PacketType_Mouse && 
                packet->Size == sizeof(MOUSE_MOVE_REQUEST)) {
                
                status = InjectMouseInput(devExt, (PMOUSE_MOVE_REQUEST)packet->Payload);
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
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// ============================================================================
// ObReferenceObjectByName Import (not in standard headers)
// ============================================================================

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);

NTKERNELAPI
POBJECT_TYPE *IoDriverObjectType;
