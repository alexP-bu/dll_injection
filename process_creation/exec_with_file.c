#include "printfile.h"

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
  //create file
  HANDLE hFile = NULL;
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
  hFile = CreateFileA(
    "outfile.txt",
    GENERIC_WRITE,
    0,
    &sa,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );
  if(!hFile){
    printf("[!] Error creating file: %d\n", GetLastError());
  }
  STARTUPINFO si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdOutput = hFile;
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
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(hFile);
  free(lpCommandLine);
  if(!PrintFileContents("outfile.txt")){
    printf("[!] Error printing file contents...");
    return -1;
  }
  return 0;
}
