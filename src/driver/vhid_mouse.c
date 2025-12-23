#include <ntddk.h>
#include <wdf.h>
#include <hidport.h>
#include "..\shared\vhid_interface.h"
#include "hid_descriptor.h"

typedef struct _DEVICE_CONTEXT {
    WDFDEVICE Device;
    WDFQUEUE  HidQueue;     // Queue for HID class requests (ReadReport)
    WDFQUEUE  ControlQueue; // Queue for user-mode movement requests
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

// Prototypes
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
EVT_WDF_DRIVER_DEVICE_ADD EvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL EvtInternalDeviceControl;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, EvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, NULL);
}

NTSTATUS EvtDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit) {
    UNREFERENCED_PARAMETER(Driver);
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFDEVICE device;
    PDEVICE_CONTEXT context;
    WDF_IO_QUEUE_CONFIG queueConfig;
    NTSTATUS status;

    // Register as a HID Minidriver
    status = HidRegisterMinidriver(DeviceInit);
    if (!NT_SUCCESS(status)) return status;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) return status;

    context = GetDeviceContext(device);
    context->Device = device;

    // Internal Queue for HID Class communication
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchManual);
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &context->HidQueue);
    if (!NT_SUCCESS(status)) return status;

    // Control Queue for user-mode IOCTLs
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &context->ControlQueue);

    return status;
}

VOID EvtInternalDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode) {
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PDEVICE_CONTEXT context = GetDeviceContext(WdfIoQueueGetDevice(Queue));
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    size_t bytesReturned = 0;

    switch (IoControlCode) {
        case IOCTL_HID_GET_DEVICE_DESCRIPTOR: {
            PVOID buffer;
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(HID_DESCRIPTOR), &buffer, NULL);
            if (NT_SUCCESS(status)) {
                PHID_DESCRIPTOR desc = (PHID_DESCRIPTOR)buffer;
                RtlZeroMemory(desc, sizeof(HID_DESCRIPTOR));
                desc->bLength = sizeof(HID_DESCRIPTOR);
                desc->bDescriptorType = HID_RESDESC_TYPE_HID;
                desc->bcdHID = 0x0110;
                desc->bCountryCode = 0;
                desc->bNumDescriptors = 1;
                desc->DescriptorList[0].bReportType = HID_RESDESC_TYPE_REPORT;
                desc->DescriptorList[0].wReportLength = MouseReportDescriptorSize;
                bytesReturned = sizeof(HID_DESCRIPTOR);
            }
            break;
        }
        case IOCTL_HID_GET_DEVICE_ATTRIBUTES: {
            PVOID buffer;
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(HID_DEVICE_ATTRIBUTES), &buffer, NULL);
            if (NT_SUCCESS(status)) {
                PHID_DEVICE_ATTRIBUTES attrib = (PHID_DEVICE_ATTRIBUTES)buffer;
                attrib->Size = sizeof(HID_DEVICE_ATTRIBUTES);
                attrib->VendorID = 0x046D;  // Logitech
                attrib->ProductID = 0xC547; // G PRO X SUPERLIGHT (Wireless Receiver)
                attrib->VersionNumber = 0x0100;
                bytesReturned = sizeof(HID_DEVICE_ATTRIBUTES);
            }
            break;
        }
        case IOCTL_HID_GET_REPORT_DESCRIPTOR: {
            PVOID buffer;
            status = WdfRequestRetrieveOutputBuffer(Request, MouseReportDescriptorSize, &buffer, NULL);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(buffer, MouseReportDescriptor, MouseReportDescriptorSize);
                bytesReturned = MouseReportDescriptorSize;
            }
            break;
        }
        case IOCTL_HID_READ_REPORT:
            // Forward to manual HID queue to wait for movement data
            status = WdfRequestForwardToIoQueue(Request, context->HidQueue);
            if (NT_SUCCESS(status)) return;
            break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

VOID EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode) {
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PDEVICE_CONTEXT context = GetDeviceContext(WdfIoQueueGetDevice(Queue));

    if (IoControlCode == IOCTL_VHID_SECURE_INPUT) {
        PVHID_SECURE_PACKET packet;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(VHID_SECURE_PACKET), (PVOID*)&packet, NULL);
        if (NT_SUCCESS(status)) {
            //
            // 1. Decrypt (XOR)
            //
            unsigned char* raw = (unsigned char*)packet;
            for (int i = 0; i < sizeof(VHID_SECURE_PACKET); i++) {
                raw[i] ^= VHID_ENCRYPTION_KEY;
            }

            //
            // 2. Dispatch based on Type
            //
            if (packet->Type == PacketType_Mouse && packet->Size == sizeof(MOUSE_MOVE_REQUEST)) {
                PMOUSE_MOVE_REQUEST move = (PMOUSE_MOVE_REQUEST)packet->Payload;
                
                WDFREQUEST hidRequest;
                status = WdfIoQueueRetrieveNextRequest(context->HidQueue, &hidRequest);
                if (NT_SUCCESS(status)) {
                    PVOID hidBuffer;
                    size_t len = 0;
                    status = WdfRequestRetrieveOutputBuffer(hidRequest, sizeof(HID_MOUSE_REPORT), &hidBuffer, &len);
                    if (NT_SUCCESS(status) && len >= sizeof(HID_MOUSE_REPORT)) {
                        PHID_MOUSE_REPORT report = (PHID_MOUSE_REPORT)hidBuffer;
                        report->ReportId = 1; // Mouse Collection
                        report->Buttons = move->buttons;
                        report->X = (char)move->dx;
                        report->Y = (char)move->dy;
                        report->Wheel = (char)move->wheel;
                        WdfRequestCompleteWithInformation(hidRequest, STATUS_SUCCESS, sizeof(HID_MOUSE_REPORT));
                    } else {
                        WdfRequestComplete(hidRequest, status);
                    }
                }
            }
            else if (packet->Type == PacketType_Keyboard && packet->Size == sizeof(KEYBOARD_INPUT_REQUEST)) {
                 // Keyboard logic would go here (requires mapping ScanCode -> HID Key)
                 // For now, we acknowledge reception.
                 status = STATUS_SUCCESS;
            }
        }
        WdfRequestComplete(Request, status);
        return;
    }

    if (IoControlCode == IOCTL_VHID_MOUSE_MOVE) {
        PMOUSE_MOVE_REQUEST moveData;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(MOUSE_MOVE_REQUEST), (PVOID*)&moveData, NULL);
        if (NT_SUCCESS(status)) {
            WDFREQUEST hidRequest;
            status = WdfIoQueueRetrieveNextRequest(context->HidQueue, &hidRequest);
            if (NT_SUCCESS(status)) {
                PVOID hidBuffer;
                status = WdfRequestRetrieveOutputBuffer(hidRequest, sizeof(HID_MOUSE_REPORT), &hidBuffer, NULL);
                if (NT_SUCCESS(status)) {
                    PHID_MOUSE_REPORT report = (PHID_MOUSE_REPORT)hidBuffer;
                    report->Buttons = moveData->buttons;
                    report->X = (char)moveData->dx;
                    report->Y = (char)moveData->dy;
                    report->Wheel = (char)moveData->wheel;
                    WdfRequestCompleteWithInformation(hidRequest, STATUS_SUCCESS, sizeof(HID_MOUSE_REPORT));
                } else {
                    WdfRequestComplete(hidRequest, status);
                }
            }
        }
        WdfRequestComplete(Request, status);
        return;
    }

    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
}
