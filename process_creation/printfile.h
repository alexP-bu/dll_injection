#include <windows.h>
#include <stdio.h>

BOOL PrintFileContents(char* filename){
  //open file
  HANDLE hFile = NULL;
  hFile = CreateFileA(
    (LPCSTR)filename,
    GENERIC_READ,
    0,
    NULL,
    3,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );
  if(hFile == INVALID_HANDLE_VALUE){
    printf("[!] Error opening file: %d\n", GetLastError());
    return FALSE;
  }
  //get file size
  DWORD dwFileSize = 0; 
  dwFileSize = GetFileSize(
    hFile, 
    NULL
  );
  if(!dwFileSize){
    printf("[!] Error getting file size: %d\n", GetLastError());
    return FALSE;
  }
  //read file
  DWORD bytesRead;
  PBYTE fileBuffer = malloc(sizeof(BYTE) * (dwFileSize + 1));
  if(!fileBuffer){
    printf("[!] Error allocating memory: %d\n", GetLastError());
    return FALSE;
  }
  if(!ReadFile(
    hFile,
    fileBuffer,
    dwFileSize,
    &bytesRead,
    NULL
  )){
    printf("Error reading file: %d\n", GetLastError());
    return FALSE;
  };
  fileBuffer[dwFileSize] = '\0';
  //print file contents
  printf("%s", fileBuffer);
  CloseHandle(hFile);
  return TRUE;
}