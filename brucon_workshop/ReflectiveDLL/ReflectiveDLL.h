#pragma once

// typedef
// Since we are looking up the functions in the EXPORT table, we'll need to define some typedefs here
typedef BOOL(APIENTRY *DLL_MAIN)(HMODULE, DWORD, LPVOID); //DLL_MAIN function, will be called to initialize CRT
typedef void(__fastcall *EntryPoint)(); //The actual Malware function

//Structure needed to hold BASE_RELOCATION_BLOCK data
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

//Structure needed to hold BASE_RELOCATION_ENTRY data
typedef struct BASE_RELOCATION_ENTRY
{
	WORD	offset : 12;
	WORD	type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

//Functions
extern "C" __declspec(dllexport) void ReflectiveInjection(PVOID pHelper);
DWORD RebaseImage(PVOID, PIMAGE_NT_HEADERS, DWORD64, PREFLECTIVE_LOADER_HELPER);
DWORD FixImports(PREFLECTIVE_LOADER_HELPER pHelper);
