#include "printfile.h"

int main(int argc, char** argv){
  DWORD dwArgsLen = 0;
  for(DWORD i = 1; i < argc; i++){
    dwArgsLen += 1; //spaces
    dwArgsLen += strlen(argv[i]);
  }
  char* lpCommandLine = malloc(
    (sizeof(char) * (strlen("cmd /c"))) + 
    (sizeof(char) * (dwArgsLen + 1)) + // +1 for null terminator
    (sizeof(char) * strlen("> outfile.txt")) 
  );
  if(!lpCommandLine){
    printf("[!] Error allocating memory for command line!");
    return -1;
  }
  //format: cmd /c program args >> outfile.txt 
  sprintf(lpCommandLine, "cmd /c");
  for(DWORD i = 1; i < argc; i++){
    sprintf(lpCommandLine + strlen(lpCommandLine), "%s ", argv[i]);
  }
  sprintf(lpCommandLine + strlen(lpCommandLine), "%s%c", "> outfile.txt", '\0');
  //printf("got command line: %s\nlen: %d\n", lpCommandLine, strlen(lpCommandLine)); //DEBUG
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
  ZeroMemory(&si, sizeof(si));
  if(!CreateProcessA(
    NULL,
    lpCommandLine,
    NULL,
    NULL,
    FALSE,
    0,
    NULL,
    NULL,
    &si,
    &pi
  )){
    printf("[!] Error creating process: %d\n", GetLastError());
    return -1;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  free(lpCommandLine);
  if(!PrintFileContents("outfile.txt")){
    printf("[!] Error printing file contents...");
    return -1;
  }
  return 0;
}
