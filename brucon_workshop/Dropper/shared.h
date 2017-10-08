#pragma once

//Define
#define WIN32_LEAN_AND_MEAN

// Windows Header Files:
#include <windows.h>

//Include necessary Header files
#include <winternl.h>
#include <inttypes.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <math.h>
#include <TlHelp32.h>
#include <WinInet.h>
#include "resource.h"
#include <tchar.h>

//Setting std namespace
using namespace std;

// Structure needed for RtlCreateUserThread
// We don't want to include the header that contains this as we want to keep our executable as small as possible, so we define it ourself
typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

//Export address entry structure, this structure is not defined in any windows header file, so we'll just make it ourself
typedef struct _IMAGE_EXPORT_ADDRESS_ENTRY {
	DWORD Address;
} IMAGE_EXPORT_ADDRESS_ENTRY, *PIMAGE_EXPORT_ADDRESS_ENTRY;

//Export address entry structure, this structure is not defined in any windows header file, so we'll just make it ourself
typedef struct _IMAGE_EXPORT_ADDRESS_BY_NAME_ENTRY {
	DWORD NameRVA;
} IMAGE_EXPORT_NAME_ENTRY, *PIMAGE_EXPORT_NAME_ENTRY;

typedef struct _IMAGE_EXPORT_NAMEORDINAL {
	WORD Ordinal;
} IMAGE_EXPORT_NAMEORDINAL, *PIMAGE_EXPORT_NAMEORDINAL;

// Typedef functions
//
// We want our executable to be free of those pesky imports as anti-malware will trip over some of those
// The only way to do this is to define these functions in the compiler and then looking them up through GetProcAddress
// In essence doing the work the windows loader does
//
// We will put all this functions into a helper structure for ease of use later. Our reflective loader will need some of these functions.
// In this case it is save to look up functions in this process and pass them to the reflectivedll in the TARGET process. 
// It's true that these are two totally different virtual memory blocks, however windows DLLs such as kernel32, ntdll, etc. ALWAYS get loaded at the EXACT same address in EVERY process
// ASLR only does it's magic at reboot, so once booted, these positions always stay the same
// Thank you Microsoft ;)

//NTDLL functions
typedef NTSTATUS(NTAPI *_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef LONG(WINAPI * _RtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T(ULONG_PTR), SIZE_T(ULONG_PTR), PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef NTSTATUS(*_RtlInsertInvertedFunctionTable)(PVOID, PVOID);
typedef NTSTATUS(*_Win7RtlInsertInvertedFunctionTable)(PDWORD64, PVOID, PVOID);
typedef NTSTATUS(*_LdrpHandleTlsData)(PLDR_DATA_TABLE_ENTRY);
typedef NTSTATUS(NTAPI *_NtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

//KERNEL32 functions
typedef HMODULE(WINAPI*_LoadLibrary)(LPCSTR);
typedef HANDLE(WINAPI *_OpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI *_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef NTSTATUS(WINAPI *_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef NTSTATUS(WINAPI *_OutputDebugString)(LPCSTR);

typedef FARPROC(WINAPI *_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef int(WINAPI *_sprintf)(PCHAR, const PCHAR, ...);

// We will define our helper structure here
// MIND YOU, it is VERY important that you understand this, DO NOT create these structures as pointers (e.g. PREFLECTIVE_LOADER_HERLPER_FUNCTIONS pFunctions)
// IF you do this, this will add a POINTER to the structure in memory as opposed to the ACTUAL structure. 
// The target process where the reflective loader function resides is in a TOTALLY different Virtual Memory block
//
// When the code tries to actually access the data located at the pointer address, everything will fail as no data will be present in the TARGET process's virtual memory
//
// This structure is a structure that will be placed inside the main HELPER structure which we will pass to the ReflectiveLoader Function, see below

typedef struct _REFLECTIVE_LOADER_HELPER_FUNCTIONS {
	//NTDLL
	_NtReadVirtualMemory __NtReadVirtualMemory;
	_NtWriteVirtualMemory __NtWriteVirtualMemory;
	_RtlCreateUserThread __RtlCreateUserThread;
	_LdrpHandleTlsData __LdrpHandleTlsData;
	_RtlInsertInvertedFunctionTable __RtlInsertInvertedFunctionTable;
	_NtQueryInformationThread __NtQueryInformationThread;

	//KERNEL32
	_LoadLibrary __LoadLibrary;
	_OpenProcess __OpenProcess;
	_VirtualAllocEx __VirtualAllocEx;
	_VirtualProtectEx __VirtualProtectEx;
	_VirtualAlloc __VirtualAlloc;
	_VirtualProtect __VirtualProtect;
	_GetProcAddress __GetProcAddress;
	_OutputDebugString __OutputDebugString;
	_sprintf __sprintf;
} REFLECTIVE_LOADER_HELPER_FUNCTIONS, *PREFLECTIVE_LOADER_HELPER_FUNCTIONS;


// The main helper structure
typedef struct _REFLECTIVE_LOADER_HELPER {
	PVOID ImageBase;
	PVOID ImportTableAddress;
	PVOID ExportTableAddress;
	PVOID TLSDirectory;
	PIMAGE_NT_HEADERS pINH;
	DWORD64 dwDelta;
	REFLECTIVE_LOADER_HELPER_FUNCTIONS ReflectiveLoaderFunctions; // This is NOT a pointer for the reasons stated above, this means that the structure will actually be present in this structure as opposed to just a pointer
} REFLECTIVE_LOADER_HELPER, *PREFLECTIVE_LOADER_HELPER;

