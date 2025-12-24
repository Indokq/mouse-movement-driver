#pragma once
#include "NeacInterface.hpp"
#include <vector>
#include <string>

struct MappedDriver {
    void* BaseAddress;
    size_t ImageSize;
    void* EntryPoint;
    void* ShellcodeAddress;  // Address of wrapper shellcode
    bool Executed;
};

class Mapper {
public:
    explicit Mapper(NeacInterface* neac);
    ~Mapper();

    bool MapDriver(const std::wstring& driverPath, MappedDriver& outDriver);
    bool ExecuteDriverEntry(MappedDriver& driver);
    bool UnmapDriver(MappedDriver& driver);

private:
    NeacInterface* m_Neac;

    // PE parsing
    bool LoadDriverFile(const std::wstring& path, std::vector<uint8_t>& buffer);
    bool ValidatePE(const uint8_t* buffer, size_t size);
    size_t GetImageSize(const uint8_t* buffer);
    
    // Cave finding for memory allocation
    struct CaveInfo {
        void* Address;
        size_t Size;
        std::wstring ModuleName;
    };
    bool FindCodeCave(size_t requiredSize, CaveInfo& outCave);
    bool FindDiscardableSection(void* moduleBase, const wchar_t* moduleName, CaveInfo& outCave);
    
    // Manual mapping
    bool CopySections(const uint8_t* buffer, void* targetBase);
    bool ProcessRelocations(const uint8_t* buffer, void* targetBase);
    bool ResolveImports(const uint8_t* buffer, void* targetBase);
    void* GetKernelProcAddress(const char* moduleName, const char* funcName);

    // Execution
    struct HookContext {
        void* OriginalAddress;
        uint8_t OriginalBytes[16];
        size_t PatchSize;
        void* HookTarget;
    };
    bool InstallExecutionHook(void* entryPoint, HookContext& ctx);
    bool TriggerExecution();
    bool RestoreHook(const HookContext& ctx);
};
