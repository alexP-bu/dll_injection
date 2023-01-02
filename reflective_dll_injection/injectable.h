#include <windows.h>
#include <stdio.h>

typedef BOOL (WINAPI* DLLMAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef BOOL (WINAPI* FreeLibrary_t)(HMODULE hModule);
typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef FARPROC (WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);
typedef LPVOID (WINAPI *VirtualAllocEx_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef int (WINAPI *MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

void* ReflectiveLoader(UINT_PTR LoadLibraryA, UINT_PTR getProcAddress);