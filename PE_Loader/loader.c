//making a custom PE loader
#include <windows.h>
BYTE* getFileBytes(char* path){
  HANDLE hFile = NULL;
  DWORD fileSize = 0;
  hFile = CreateFileA(path,
                      GENERIC_READ,
                      0,
                      NULL,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      NULL);
  if (hFile == INVALID_HANDLE_VALUE){
    printf("[!] ERROR: failed to read file....");
    return NULL;
  }
  fileSize = GetFileSize(hFile, NULL);
  if(fileSize == 0){
    printf("[!] ERROR: no file, or empty file given...");
    return NULL;
  }
  BYTE* buffer = (BYTE*) malloc(fileSize * sizeof(BYTE) + 1);
  if (!buffer){
    printf("[!] ERROR: failed to allocate memory to read file bytes...");
    return NULL;
  }
  DWORD read = 0;
  if(!ReadFile(hFile, buffer, fileSize, &read, NULL)){
    printf("[!] ERROR: failed to read file bytes...");
    return NULL;
  }
  buffer[fileSize] = "\0";
  return buffer;
}

int main(int argc, char const *argv[]){
  if (argc < 2){
    printf("[!] USAGE: loader.exe <path_to_file>");
    return 1;
  }
  //first, read file bytes
  BYTE* fileBytes = getFileBytes(argv[1]);
  if(!fileBytes){
    printf("[!] ERROR getting file bytes. Exiting...");
    return 1;
  }

  return 0;
}
