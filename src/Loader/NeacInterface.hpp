#pragma once
#include <Windows.h>
#include <cstdint>

class NeacInterface {
public:
    NeacInterface();
    ~NeacInterface();

    bool Initialize();
    void Shutdown();
    bool IsConnected() const { return m_hPort != INVALID_HANDLE_VALUE; }

    // Kernel primitives
    bool KernelRead(void* dest, void* src, uint32_t size);
    bool KernelWrite(void* dest, void* src, uint32_t size);
    bool ProtectMemory(uint32_t pid, void* addr, uint32_t size, uint32_t newProtect);

    // Process primitives
    void* GetProcessBase(uint32_t pid);
    bool ReadProcessMemory(uint32_t pid, void* addr, uint32_t size, void* out);
    bool WriteProcessMemory(uint32_t pid, void* addr, uint32_t size, void* in);

    // Kernel info
    void* GetKernelBase();
    void* GetPsLoadedModuleList();
    void* FindKernelModule(const wchar_t* moduleName);
    void* GetKernelExport(const char* funcName);

private:
    HANDLE m_hPort;
    void* m_KernelBase;
    void* m_PsLoadedModuleList;
    void* m_SsdtItems[0x1000];

    uint32_t GetExportRva(const char* funcName);
    uint32_t ParseExportRva(const uint8_t* moduleBase, const char* funcName);
};
