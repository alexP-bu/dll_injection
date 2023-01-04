//idea from https://github.com/m0n0ph1/Process-Hollowing
#include <windows.h>

int main(int argc, char* argv[]){
    //first create a process in suspended state
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    if(!CreateProcessA(NULL, 
                       NULL, 
                       NULL, 
                       NULL, 
                       FALSE, 
                       CREATE_SUSPENDED, 
                       NULL, 
                       NULL, 
                       &si, 
                       &si)){
        printf("[!] ERROR CREATING PROCESS");
        //next, find the base address from the PEB block

        //then, read the NT headers

        //after this, unmap destination section with NtUnmapViewOfSection

        //allocate memory for new image with virtuallocex, 
        //the image base stored must be set to the destination image base address
        //the optional header needs to be patched

        //copy the image with writeprocessmemory
        
        //rebase the source image with the .reloc section, IMAGE_DATA_DIRECTORY (IMAGE_DIRECTORY_ENTRY_BASERELOC)

        //with the source image loaded into the target process, update EAX register with the thread context

        //resume the thread
    }
    return 0;
}
