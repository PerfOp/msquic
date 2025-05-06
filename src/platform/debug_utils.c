#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#pragma comment(lib, "dbghelp.lib")
#endif

void PrintCallStack() {
#ifdef _WIN32
    //Init the symbol handler
    HANDLE process = GetCurrentProcess();
    SymInitialize(process, NULL, TRUE);

    //Capture the current stack
    void* stack[100];
    USHORT frames = CaptureStackBackTrace(0, 100, stack, NULL);

    //Allocating memory to store the symbol info
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
    if (symbol != NULL) {
        symbol->MaxNameLen = 255;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

        //Print the stack
        for (USHORT i = 0; i < frames; i++) {
            SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);
            printf("%d: %s - 0x%0llX\n", frames - i - 1, symbol->Name, symbol->Address);
        }

        //Clean the resource
        free(symbol);
    }
    SymCleanup(process);
#endif
}
