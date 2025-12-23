# VHID Mouse Driver

This project implements a Virtual HID Source Driver for Windows, designed to inject mouse input into the system stack cleanly and professionally.

## Features
- **Composite Emulation**: Mimics full Logitech Receiver with Mouse, Keyboard, and Vendor interfaces.
- **Custom Identity**: Spoofs a Logitech G PRO X SUPERLIGHT (VID 0x046D / PID 0xC547).
- **Secure Input**: Support for `IOCTL_VHID_SECURE_INPUT` with XOR packet obfuscation.
- **5-Button Support**: Supports Left, Right, Middle, X1, and X2 buttons.
- **Stealth**: No hooks, no manual callback tracing, no integrity check violations.

## Directory Structure
- `src/driver`: Kernel driver source code.
- `src/shared`: Shared IOCTL definitions (including encryption structs).
- `src/driver/vhid_mouse.inf`: Installation file.

## Build Instructions
1. Install **Visual Studio 2022** with "Desktop development with C++".
2. Install the **Windows Driver Kit (WDK)**.
3. Open `mousedrive.sln`.
4. Build the solution (Release / x64).

## Installation
1. Enable Test Signing (if self-signing):
   ```powershell
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
2. Install using `devcon` (included in WDK):
   ```powershell
   devcon install src\driver\vhid_mouse.inf "HID\VID_046D&PID_C547"
   ```

## Usage
Interact with the driver using `IOCTL_VHID_MOUSE_MOVE` (Legacy) or `IOCTL_VHID_SECURE_INPUT` (Encrypted).
The encryption key is defined in `src/shared/vhid_interface.h`.
To use secure input:
1. Populate `VHID_SECURE_PACKET` with your input data.
2. XOR the entire packet with `VHID_ENCRYPTION_KEY`.
3. Send via `DeviceIoControl`.
