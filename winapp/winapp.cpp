#include <windows.h>
#include <stdio.h>


https://github.com/JustasMasiulis/lazy_importer
#include "lazy_importer.hpp"
https://github.com/kokke/tiny-AES-c
#include "aes.hpp"
//the header that contains our exe file to encrypt.
#include "he.h"


#pragma function(memcpy, memset)










//custom crt functions implementation

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
	
	SIZE_T shellcodeSize = sizeof(rawData);
// the key to encrypt your exe file with. Keep in mind that if you want to keep the default initialization vector (iv), the key MUST be 32 characters long. Make sure that both variables are the same as these ones in the loader.
	unsigned char key[] = "qwertyuiopasdfghjklzxcvbnmqwerty";
	// default initialization vector used for this project. you may change it if you want to.
	unsigned char iv[] = "\x9d\x02\x35\x3b\xa3\x4b\xec\x26\x13\x88\x58\x51\x11\x47\xa5\x98";

	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_encrypt_buffer(&ctx, rawData, shellcodeSize);
// create our output file for the encrypted data.
	HANDLE file =CreateFileA("final.bin", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0;
	// write the encrypted data to it
	WriteFile(file, rawData, sizeof(rawData), &written, NULL);
	// close the handle.
	CloseHandle(file);
	MessageBoxA(0, "Your Exe File Has Been Encrypted Successfully.", "Success", 0);
	ExitProcess(0);
	
}
