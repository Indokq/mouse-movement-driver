#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <hidport.h>

//
// IOCTL definitions for user-mode communication
//
#define VHID_MOUSE_DEVICE_TYPE 0x8000

#define IOCTL_VHID_MOUSE_MOVE \
    CTL_CODE(VHID_MOUSE_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Data structure for mouse movement
//
typedef struct _MOUSE_MOVE_REQUEST {
    long dx;                // Relative X movement
    long dy;                // Relative Y movement
    unsigned char buttons;  // Bitmask: 1=Left, 2=Right, 4=Middle, 8=X1, 16=X2
    unsigned char wheel;    // Vertical wheel movement
} MOUSE_MOVE_REQUEST, *PMOUSE_MOVE_REQUEST;

//
// HID Mouse Report (as defined in the descriptor)
//
typedef struct _HID_MOUSE_REPORT {
    unsigned char Buttons;
    char X;
    char Y;
    char Wheel;
} HID_MOUSE_REPORT, *PHID_MOUSE_REPORT;
