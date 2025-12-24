#pragma once
#include "NeacInterface.hpp"
#include <cstdint>

class SyscallHijack {
public:
    explicit SyscallHijack(NeacInterface* neac);
    ~SyscallHijack();

    // Main interface - allocate kernel pool via syscall hijack
    void* AllocateKernelPool(size_t size);

    // Cleanup - must be called to restore system state
    void Cleanup();

private:
    NeacInterface* m_Neac;
    
    // Kernel addresses
    void* m_KiServiceTable;
    void* m_KeServiceDescriptorTableShadow;
    void* m_PteBase;
    void* m_ExAllocatePool2;
    uint32_t m_SsdtSize;
    bool m_IsPool2;  // true if using ExAllocatePool2, false if ExAllocatePoolWithTag

    // Hijack state
    int m_HijackedSyscallIndex;
    uint32_t m_OriginalSyscallOffset;
    void* m_ShellcodeAddress;
    size_t m_ShellcodeSize;
    
    // PDE state
    void* m_KiServiceTablePDE;
    uint64_t m_OriginalPDEFlags;
    bool m_PDEModified;

    // Shared memory for result
    void* m_SharedMemory;
    void* m_SharedMemoryKernel;

    // Initialization
    bool Initialize();
    bool FindKernelAddresses();
    bool FindPteBase();
    void* FindSsdtViaPatternScan(void* startAddr);
    
    // Syscall discovery
    int FindUnusedSyscall();
    void* GetSyscallHandler(int index);
    bool IsStubFunction(const uint8_t* bytes, size_t len);
    
    // PDE/PTE manipulation
    void* GetPDEAddress(void* virtualAddress);
    void* GetPTEAddress(void* virtualAddress);
    bool FlipPDEWriteBit();
    bool RestorePDE();
    bool MakeAddressExecutable(void* address);
    bool MakeAddressWritable(void* address);
    
    // CR0.WP bypass shellcode
    bool InjectCR0WPBypassShellcode();
    void* m_CR0BypassShellcode;
    
    // Shellcode injection
    bool FindShellcodeLocation();
    bool InjectShellcode();
    
    // Syscall hijack
    bool HijackSyscall();
    bool RestoreSyscall();
    
    // Execution
    bool ExecuteHijackedSyscall(size_t size, void* outputAddr);
};
