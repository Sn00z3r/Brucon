#pragma once

//Define
#define REBASE(pRVA, baseOld, baseNew)       ((uint64_t)pRVA - (uint64_t)baseOld + (uint64_t)baseNew)  //Quick define to rebase an address based on RVA, Original Base and New Base


// Windows Header Files:
#include "shared.h"
#include <iostream>
// FUNCTIONS
//Entry
DWORD Inject(PCHAR, HMODULE);

//Initialization
DWORD InitHelperFunctions();
DWORD InitInject();
DWORD InitPEHeaderInfo();
DWORD GetResource(PVOID*, PDWORD);
DWORD InitHelper();
DWORD GetNonExportedNTDLLFunctions();

// Allocation and Writing
DWORD AllocateMemory();
DWORD WriteMemory();

// Protecting memory and helper functions
// executable, readable, writable
DWORD ProtectMemory();
DWORD secp_to_vmemp(DWORD secp);
DWORD protect_remote_secs(HANDLE proc, void *base, const IMAGE_NT_HEADERS *snthdrs);

// Execute ReflectiveLoader
DWORD ExecuteReflectiveLoader();

// General functions
DWORD GetProcessByName(PCHAR processName, DWORD * id);

// Locating memory offset functions (Boyer-Moore)
DWORD findOffset(const PCHAR pPattern, std::vector<uint64_t>& vOffset, uint64_t value_offset = 0);

//###########################################################################################################################################################################################################################################################################
//Following functions and structures are not part of the injecting process, they are used to determine what steps you have performed correctly.
// DO NOT CHANGE THESE

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

typedef struct UNITTEST {
	DWORD64 LdrpHandleTlsData;
	DWORD64 RtlInsertInvertedFunctionTable;
	DWORD64 dwAddressHelper;
	DWORD64 dwAddressDLL;
	HANDLE process;
	DWORD64 dwThreadEntry;
	PREFLECTIVE_LOADER_HELPER ReflectiveLoaderHelper;
}UNITTEST, *PUNITTEST;

typedef DWORD(__fastcall *Check)(PUNITTEST,DWORD);
typedef DWORD(__fastcall *GetRelocationEntriesDefault)(HANDLE,PVOID, PREFLECTIVE_LOADER_HELPER);
DWORD CheckProgress();
