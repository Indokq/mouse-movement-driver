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

#define IOCTL_VHID_SECURE_INPUT \
    CTL_CODE(VHID_MOUSE_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Shared Seed for XOR Obfuscation (Simple example)
// In production, negotiate this dynamically or use a stronger algorithm.
//
#define VHID_ENCRYPTION_KEY 0xAB

//
// Packet Types for Secure Input
//
typedef enum _VHID_PACKET_TYPE {
    PacketType_Mouse = 1,
    PacketType_Keyboard = 2
} VHID_PACKET_TYPE;

//
// Encrypted Container
// User-mode should fill 'Payload', then XOR the entire struct with VHID_ENCRYPTION_KEY
//
typedef struct _VHID_SECURE_PACKET {
    unsigned char Type; // VHID_PACKET_TYPE
    unsigned char Size; // Size of Payload
    unsigned char Payload[16]; // Holds MOUSE_MOVE_REQUEST or KEYBOARD_INPUT_REQUEST
} VHID_SECURE_PACKET, *PVHID_SECURE_PACKET;

//
// Keyboard Input Data
//
typedef struct _KEYBOARD_INPUT_REQUEST {
    unsigned short MakeCode; // Scan code
    unsigned short Flags;    // 1=E0, 2=E1, 4=Term, 8=Break
    unsigned short Reserved;
} KEYBOARD_INPUT_REQUEST, *PKEYBOARD_INPUT_REQUEST;

//
// HID Keyboard Report (Boot Protocol)
//
typedef struct _HID_KEYBOARD_REPORT {
    unsigned char ReportId; // 2
    unsigned char Modifiers;
    unsigned char Reserved;
    unsigned char Keys[6];
} HID_KEYBOARD_REPORT, *PHID_KEYBOARD_REPORT;

//
// HID Mouse Report (Updated with Report ID)
//
typedef struct _HID_MOUSE_REPORT {
    unsigned char ReportId; // 1
    unsigned char Buttons;
    char X;
    char Y;
    char Wheel;
} HID_MOUSE_REPORT, *PHID_MOUSE_REPORT;

