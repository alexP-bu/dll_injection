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
  LARGE_INTEGER liFileSize; 
  ZeroMemory(&liFileSize, sizeof(LARGE_INTEGER));
  if(!GetFileSizeEx(
    hFile, 
    &liFileSize
  )){
    printf("[!] Error getting file size: %d\n", GetLastError());
    return -1;
  };
  //read file
  DWORD bytesRead;
  PBYTE fileBuffer = malloc(sizeof(BYTE) * (liFileSize.QuadPart + 1));
  if(!fileBuffer){
    printf("[!] Error allocating memory: %d\n", GetLastError());
    return FALSE;
  }
  if(!ReadFile(
    hFile,
    fileBuffer,
    liFileSize.QuadPart,
    &bytesRead,
    NULL
  )){
    printf("Error reading file: %d\n", GetLastError());
    return FALSE;
  };
  fileBuffer[liFileSize.QuadPart] = '\0';
  //print file contents
  printf("%s", fileBuffer);
  CloseHandle(hFile);
  return TRUE;
}