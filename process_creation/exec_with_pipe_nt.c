#include "printfile.h"

#define BUFSIZE 4096
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess()((HANDLE)(LONG_PTR)-1)

typedef NTSTATUS (NTAPI* ntAllocateVirtualMemory)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
);

typedef NTSTATUS (NTAPI* ntFreeVirtualMemory)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
);

BOOL readFromPipe(HANDLE hReadPipe, PBYTE lpBuffer){
  DWORD lpTotalBytesAvail = 0;
  if(!PeekNamedPipe(
    hReadPipe,
    NULL,
    0,
    NULL,
    &lpTotalBytesAvail,
    NULL
  )){
    printf("[!] Error peeking pipe: %d\n", GetLastError());
    return FALSE;
  };
  while(lpTotalBytesAvail > 0){
    DWORD lpNumberOfBytesRead = 0;
    if(!ReadFile(
      hReadPipe,
      lpBuffer,
      BUFSIZE - 1,
      &lpNumberOfBytesRead,
      NULL
    )){
      printf("[!] Error reading contents of pipe: %d\n", GetLastError());
      return FALSE;
    };
    lpBuffer[lpNumberOfBytesRead] = '\0';
    printf("%s", lpBuffer);
    lpTotalBytesAvail -= lpNumberOfBytesRead;
  }
  return TRUE;
}

int main(int argc, char** argv){
  
  //lets get ntdll and functions we need from it
  HANDLE hProcess = NULL;
  hProcess = NtCurrentProcess();
  if(!hProcess){
    printf("[!] Error getting current process: %d\n", GetLastError());
    return -1;
  }
  HMODULE hNtdll = NULL;
  hNtdll = LoadLibraryA("ntdll");
  if(!hNtdll){
    printf("[!] Error loading ntdll: %d\n", GetLastError());
    return -1;
  }
  FARPROC fpNtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
  FARPROC fpNtFreeVirtualMemory = GetProcAddress(hNtdll, "NtFreeVirtualMemory");
  ntAllocateVirtualMemory NtAllocateVirtualMemory = (ntAllocateVirtualMemory)fpNtAllocateVirtualMemory;
  ntFreeVirtualMemory NtFreeVirtualMemory = (ntFreeVirtualMemory)fpNtFreeVirtualMemory;

  //get length of command line args
  SIZE_T dwArgsLen = 0;
  for(SIZE_T i = 1; i < argc; i++){
    dwArgsLen += 1; //spaces
    dwArgsLen += strlen(argv[i]);
  }

  //let's remove our use of malloc by using HeapCreate, HeapAlloc, HeapFree, HeapDestroy
  //finally let's bypass HeapAlloc with a direct call to NtAllocateVirtualMemory
  NTSTATUS ntStatus;
  SIZE_T stCommandLine = (sizeof(BYTE) * (strlen("cmd /c "))) + (sizeof(BYTE) * (dwArgsLen + 1));
  PVOID lpCommandLine = 0;
  ntStatus = NtAllocateVirtualMemory(
    hProcess,
    (PVOID)&lpCommandLine,
    0,
    &stCommandLine,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error allocating virtual memory for command line: %x\n", ntStatus);
    return -1;
  }

  //format: cmd /c program arg0 arg1 
  sprintf(lpCommandLine, "cmd /c ");
  for(DWORD i = 1; i < argc; i++){
    sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), "%s ", argv[i]);
  }
  sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), "%c", '\0');
  //printf("got command line: %s\nlen: %d\n", lpCommandLine, strlen(lpCommandLine)); //DEBUG

  //create pipe
  HANDLE hReadPipe;
  HANDLE hWritePipe;
  SECURITY_ATTRIBUTES sa;
  RtlZeroMemory(&sa, sizeof(sa));

  //createpipe calls NtOpenFile
  if(!CreatePipe(
    &hReadPipe,
    &hWritePipe,
    &sa,
    BUFSIZE
  )){
    printf("[!] Error creating pipe: %d\n", GetLastError());
    return -1;
  };

  //make sure only write end is inherited
  //instead of using sethandleinformation, we can use ntqueryobject + ntsetinformationobject
  if(!SetHandleInformation(
    hWritePipe, 
    HANDLE_FLAG_INHERIT, 
    TRUE
  )){
    printf("[!] Error setting handle information: %d\n", GetLastError());
    return -1;
  };

  //create process
  STARTUPINFO si;
  RtlZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.dwFlags = STARTF_USESTDHANDLES;
  PROCESS_INFORMATION pi;
  RtlZeroMemory(&pi, sizeof(pi));
  if(!CreateProcessA(
    NULL,
    lpCommandLine,
    NULL,
    NULL,
    TRUE,
    0,
    NULL,
    NULL,
    &si,
    &pi
  )){
    printf("[!] Error creating process: %d\n", GetLastError());
    return -1;
  }

  //read from pipe
  PBYTE lpBuffer = NULL;
  SIZE_T stBufferSize = (SIZE_T)(sizeof(BYTE) * BUFSIZE);
  ntStatus = NtAllocateVirtualMemory(
    hProcess,
    (PVOID)&lpBuffer,
    0,
    &stBufferSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error allocating virtual memory for output buffer: %x", ntStatus);
    return -1;
  }
  while(WaitForSingleObject(pi.hProcess, 50)){
    if(!readFromPipe(hReadPipe, lpBuffer)){
      return -1;
    }
  }
  //print any remaining output
  if(!readFromPipe(hReadPipe, lpBuffer)){
    return -1;
  }
  //cleanup
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(hWritePipe);
  CloseHandle(hReadPipe);
  ntStatus = NtFreeVirtualMemory(
    hProcess,
    &lpCommandLine,
    &stCommandLine,
    MEM_RELEASE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error freeing commandline memory, %x\n", ntStatus);
    return -1;
  }
  ntStatus = NtFreeVirtualMemory(
    hProcess,
    (PVOID)&lpBuffer,
    &stBufferSize,
    MEM_RELEASE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error freeing output buffer memory, %x\n", ntStatus);
    return -1;
  }
  return 0;
}