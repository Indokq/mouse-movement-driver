# VHID Mouse Driver

This project implements a Virtual HID Source Driver for Windows, designed to inject mouse input into the system stack cleanly and professionally.

## Features
- **KMDF Architecture**: Uses official Microsoft Kernel-Mode Driver Framework.
- **HID Source**: Registers as a legitimate HID Minidriver.
- **Custom Identity**: Spoofs a Logitech G PRO X SUPERLIGHT (VID 0x046D / PID 0xC547).
- **5-Button Support**: Supports Left, Right, Middle, X1, and X2 buttons.
- **Stealth**: No hooks, no manual callback tracing, no integrity check violations.

## Directory Structure
- `src/driver`: Kernel driver source code.
- `src/shared`: Shared IOCTL definitions.
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
   devcon install src\driver\vhid_mouse.inf "Root\VirtualHIDMouse"
   ```

## Usage
Interact with the driver using `IOCTL_VHID_MOUSE_MOVE` (Code `0x801`).
See `src/shared/vhid_interface.h` for the packet structure.
