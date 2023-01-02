#include <windows.h>

//compile with command: gcc -shared -o injectable.dll injectable.c

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    switch(fdwReason){
        case DLL_PROCESS_ATTACH: {
            MessageBoxA(NULL, "hello world, from inside your process ^_^", "sp00ky", 0x00000000L);
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}