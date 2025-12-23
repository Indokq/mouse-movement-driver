#pragma once

//
// Standard HID Mouse Report Descriptor
// This defines a mouse with 3 buttons, X and Y relative movement, and a wheel.
//
const unsigned char MouseReportDescriptor[] = {
    // -------------------------------------------------
    // Report ID 1: Mouse (Standard 5-button)
    // -------------------------------------------------
    0x05, 0x01,        // USAGE_PAGE (Generic Desktop)
    0x09, 0x02,        // USAGE (Mouse)
    0xA1, 0x01,        // COLLECTION (Application)
    0x85, 0x01,        //   REPORT_ID (1)
    0x09, 0x01,        //   USAGE (Pointer)
    0xA1, 0x00,        //   COLLECTION (Physical)
    0x05, 0x09,        //     USAGE_PAGE (Button)
    0x19, 0x01,        //     USAGE_MINIMUM (Button 1)
    0x29, 0x05,        //     USAGE_MAXIMUM (Button 5)
    0x15, 0x00,        //     LOGICAL_MINIMUM (0)
    0x25, 0x01,        //     LOGICAL_MAXIMUM (1)
    0x95, 0x05,        //     REPORT_COUNT (5)
    0x75, 0x01,        //     REPORT_SIZE (1)
    0x81, 0x02,        //     INPUT (Data,Var,Abs)
    0x95, 0x01,        //     REPORT_COUNT (1)
    0x75, 0x03,        //     REPORT_SIZE (3) - Padding
    0x81, 0x03,        //     INPUT (Cnst,Var,Abs)
    0x05, 0x01,        //     USAGE_PAGE (Generic Desktop)
    0x09, 0x30,        //     USAGE (X)
    0x09, 0x31,        //     USAGE (Y)
    0x09, 0x38,        //     USAGE (Wheel)
    0x15, 0x81,        //     LOGICAL_MINIMUM (-127)
    0x25, 0x7F,        //     LOGICAL_MAXIMUM (127)
    0x75, 0x08,        //     REPORT_SIZE (8)
    0x95, 0x03,        //     REPORT_COUNT (3)
    0x81, 0x06,        //     INPUT (Data,Var,Rel)
    0xC0,              //   END_COLLECTION
    0xC0,              // END_COLLECTION

    // -------------------------------------------------
    // Report ID 2: Keyboard (Boot Interface)
    // -------------------------------------------------
    0x05, 0x01,        // USAGE_PAGE (Generic Desktop)
    0x09, 0x06,        // USAGE (Keyboard)
    0xA1, 0x01,        // COLLECTION (Application)
    0x85, 0x02,        //   REPORT_ID (2)
    0x05, 0x07,        //   USAGE_PAGE (Keyboard)
    0x19, 0xE0,        //   USAGE_MINIMUM (Keyboard LeftControl)
    0x29, 0xE7,        //   USAGE_MAXIMUM (Keyboard Right GUI)
    0x15, 0x00,        //   LOGICAL_MINIMUM (0)
    0x25, 0x01,        //   LOGICAL_MAXIMUM (1)
    0x75, 0x01,        //   REPORT_SIZE (1)
    0x95, 0x08,        //   REPORT_COUNT (8)
    0x81, 0x02,        //   INPUT (Data,Var,Abs)
    0x95, 0x01,        //   REPORT_COUNT (1)
    0x75, 0x08,        //   REPORT_SIZE (8)
    0x81, 0x03,        //   INPUT (Cnst,Var,Abs)
    0x95, 0x05,        //   REPORT_COUNT (5)
    0x75, 0x01,        //   REPORT_SIZE (1)
    0x05, 0x08,        //   USAGE_PAGE (LEDs)
    0x19, 0x01,        //   USAGE_MINIMUM (Num Lock)
    0x29, 0x05,        //   USAGE_MAXIMUM (Kana)
    0x91, 0x02,        //   OUTPUT (Data,Var,Abs)
    0x95, 0x01,        //   REPORT_COUNT (1)
    0x75, 0x03,        //   REPORT_SIZE (3)
    0x91, 0x03,        //   OUTPUT (Cnst,Var,Abs)
    0x95, 0x06,        //   REPORT_COUNT (6)
    0x75, 0x08,        //   REPORT_SIZE (8)
    0x15, 0x00,        //   LOGICAL_MINIMUM (0)
    0x25, 0x65,        //   LOGICAL_MAXIMUM (101)
    0x05, 0x07,        //   USAGE_PAGE (Keyboard)
    0x19, 0x00,        //   USAGE_MINIMUM (Reserved (no event indicated))
    0x29, 0x65,        //   USAGE_MAXIMUM (Keyboard Application)
    0x81, 0x00,        //   INPUT (Data,Ary,Abs)
    0xC0,              // END_COLLECTION

    // -------------------------------------------------
    // Report ID 3: Vendor Defined (Logitech Mimic)
    // -------------------------------------------------
    0x06, 0x00, 0xFF,  // USAGE_PAGE (Vendor Defined 0xFF00)
    0x09, 0x01,        // USAGE (Vendor Usage 1)
    0xA1, 0x01,        // COLLECTION (Application)
    0x85, 0x03,        //   REPORT_ID (3)
    0x15, 0x00,        //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00,  //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,        //   REPORT_SIZE (8)
    0x95, 0x20,        //   REPORT_COUNT (32 bytes)
    0x09, 0x01,        //   USAGE (Vendor Usage 1)
    0x81, 0x02,        //   INPUT (Data,Var,Abs)
    0x09, 0x01,        //   USAGE (Vendor Usage 1)
    0x91, 0x02,        //   OUTPUT (Data,Var,Abs)
    0xC0               // END_COLLECTION
};

const unsigned short MouseReportDescriptorSize = sizeof(MouseReportDescriptor);
