//idea from https://github.com/m0n0ph1/Process-Hollowing
#include <windows.h>
#include <stdio.h>
#include <types.h>

int main(int argc, char* argv[]){
    //first create a process in suspended state
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    if(!CreateProcessA(
        NULL,
        "svchost", // let's use svchost as our process
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)){
        printf("[!] Error creating process %d\n", GetLastError());
        return 1;
    }
    //load ntdll and get our native function
    HMODULE hNtdll = LoadLibraryA("ntdll");
    FARPROC adrNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess) adrNtQueryInformationProcess;
    //find the base address from the PEB block
    PROCESS_BASIC_INFORMATION pbi;
    DWORD returnLength = 0;
    if(!NtQueryInformationProcess(
        pi.hProcess, 
        ProcessBasicInformation, 
        pbi, 
        sizeof(PROCESS_BASIC_INFORMATION), 
        &returnLength) != 0){
        printf("[!] Error querying process information: %d", GetLastError());
        return 1;
    }
    printf("Got session ID: %x\n", pbi->PebBaseAddress);
    //read the NT headers
    //unmap destination section with NtUnmapViewOfSection
    //allocate memory for new image with virtuallocex, 
    //the image base stored must be set to the destination image base address
    //the optional header needs to be patched
    //copy the image with writeprocessmemory
    
    //rebase the source image with the .reloc section, IMAGE_DATA_DIRECTORY (IMAGE_DIRECTORY_ENTRY_BASERELOC)
    //with the source image loaded into the target process, update EAX register with the thread context
    //resume the thread
    return 0;
}
