#include "printfile.h"

#define BUFSIZE 1024

BOOL readFromPipe(HANDLE hReadPipe){
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
  if(lpTotalBytesAvail > 0){
    BYTE* lpBuffer = malloc(sizeof(BYTE) * (lpTotalBytesAvail + 1));
    DWORD lpNumberOfBytesRead = 0;
    if(!ReadFile(
      hReadPipe,
      lpBuffer,
      lpTotalBytesAvail,
      &lpNumberOfBytesRead,
      NULL
    )){
      printf("[!] Error reading contents of pipe: %d\n", GetLastError());
      return FALSE;
    };
    lpBuffer[lpTotalBytesAvail] = '\0';
    printf("%s", lpBuffer);
    free(lpBuffer);
    lpTotalBytesAvail = 0;
  }
  return TRUE;
}

int main(int argc, char** argv){
  DWORD dwArgsLen = 0;
  for(DWORD i = 1; i < argc; i++){
    dwArgsLen += 1; //spaces
    dwArgsLen += strlen(argv[i]);
  }
  char* lpCommandLine = malloc(
    (sizeof(char) * (strlen("cmd /c "))) + 
    (sizeof(char) * (dwArgsLen + 1)) // +1 for null terminator 
  );
  if(!lpCommandLine){
    printf("[!] Error allocating memory for command line!");
    return -1;
  }
  //format: cmd /c program arg0 arg1 
  sprintf(lpCommandLine, "cmd /c ");
  for(DWORD i = 1; i < argc; i++){
    sprintf(lpCommandLine + strlen(lpCommandLine), "%s ", argv[i]);
  }
  sprintf(lpCommandLine + strlen(lpCommandLine), "%c", '\0');
  //printf("got command line: %s\nlen: %d\n", lpCommandLine, strlen(lpCommandLine)); //DEBUG
  //create pipe
  HANDLE hReadPipe;
  HANDLE hWritePipe;
  SECURITY_ATTRIBUTES sa;
  ZeroMemory(&sa, sizeof(sa));
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
  if(!SetHandleInformation(
    hWritePipe, 
    HANDLE_FLAG_INHERIT, 
    TRUE
  )){
    printf("[!] Error setting handle information: %d\n", GetLastError());
    return -1;
  };
  STARTUPINFO si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.dwFlags = STARTF_USESTDHANDLES;
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
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
  while(WaitForSingleObject(pi.hProcess, 50)){
    if(!readFromPipe(hReadPipe)){
      return -1;
    }
  }
  //print any remaining output
  if(!readFromPipe(hReadPipe)){
    return -1;
  }
  //cleanup
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(hWritePipe);
  CloseHandle(hReadPipe);
  free(lpCommandLine);
  return 0;
}