#include <Windows.h>
#include <winternl.h>
#include <minwindef.h>
#include <minwinbase.h>
#include <winnt.h>

#pragma code_seg(".code")

//======================================================================
// fileapi.h
typedef HANDLE (WINAPI *__CreateFileA) (
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
);
typedef BOOL (WINAPI *__WriteFile) (
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);
// handleapi.h
typedef BOOL (WINAPI *__CloseHandle) (
    _In_ _Post_ptr_invalid_ HANDLE hObject
);
// processthreadsapi.h
typedef void (WINAPI *__ExitProcess) (
    _In_ UINT uExitCode
);
//======================================================================

typedef struct SHELL_CODE_SUPER_BLOCK {
    // function
    __CreateFileA _CreateFileA;
    __WriteFile _WriteFile;
    __CloseHandle _CloseHandle;
    __ExitProcess _ExitProcess;
    // headers
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_FILE_HEADER fileHdr;
    IMAGE_OPTIONAL_HEADER32 optHdr;
    IMAGE_SECTION_HEADER lasSecHdr, newSecHdr;
} SCSB;

//======================================================================

#define CreateFileA sb->_CreateFileA
#define WriteFile sb->_WriteFile
#define CloseHandle sb->_CloseHandle
#define ExitProcess sb->_ExitProcess

//======================================================================

typedef struct _IMAGE_EXPORT_ADDRESS_TABLE_ {
    union {
        DWORD dwExportRVA;
        DWORD dwForwarderRVA;
    };
} IMAGE_EXPORT_ADDRESS_TABLE, *PIMAGE_EXPORT_ADDRESS_TABLE;

typedef PCHAR IMAGE_EXPORT_NAME_POINTER ;
typedef PCHAR *PIMAGE_EXPORT_NAME_POINTER;

typedef WORD IMAGE_EXPORT_ORDINAL_TABLE;
typedef WORD *PIMAGE_EXPORT_ORDINAL_TABLE;

//======================================================================

__forceinline int _strcmp(const char *s1, const char *s2) {
    while(*s1 || *s2) {
        if(*s1 != *s2) return *s1 < *s2 ? -1 : 1;
        s1++, s2++;
    }
    return 0;
}

__forceinline DWORD FindFunction(
        PCHAR pcFuncName,
        DWORD DemandModuleBase
    ) {
    // Find address of EXPORT Directory Table
    PIMAGE_DOS_HEADER pDosHdr =  DemandModuleBase;
    PIMAGE_FILE_HEADER pFileHdr = DemandModuleBase
        + pDosHdr->e_lfanew + 0x4; /* 0x4 for signature */
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = (BYTE *)pFileHdr + sizeof(IMAGE_FILE_HEADER);
    PIMAGE_EXPORT_DIRECTORY d = DemandModuleBase
        + pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_ADDRESS_TABLE pAddr = DemandModuleBase + d->AddressOfFunctions;
    PIMAGE_EXPORT_NAME_POINTER ppName = DemandModuleBase + d->AddressOfNames;
    PIMAGE_EXPORT_ORDINAL_TABLE pOrd = DemandModuleBase + d->AddressOfNameOrdinals;
    for (SIZE_T i = 0; i < d->NumberOfNames; i++) {
        if (_strcmp(DemandModuleBase + ppName[i], pcFuncName) == 0) {
            // Matched
            WORD ord = pOrd[i];
            DWORD FuncVA = DemandModuleBase + (pAddr + ord)->dwExportRVA;
            return FuncVA;
        }
    }
    return 0;
}

__forceinline DWORD FindBase(PWCHAR DemandModuleName, PEB *peb) {
    // Find ImageBase of kernel32.dll
    size_t DemandModuleNameLen = sizeof(DemandModuleName) / sizeof(WCHAR);  
    DWORD DemandModuleBase = 0;
    PPEB_LDR_DATA pLdr = peb->Ldr;
    LIST_ENTRY LdrDataListHead = pLdr->InMemoryOrderModuleList;
    for (PRLIST_ENTRY e = LdrDataListHead.Flink; 1 ; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(
            e,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        
        // Compare name with DemandModuleName
        PWCHAR s = ((UNICODE_STRING *)Module->Reserved4)->Buffer; /* BaseDllName*/
        for (int k = 0; k < DemandModuleNameLen; k++) {
            if (s[k] != DemandModuleName[k])
                break;
            if (k == DemandModuleNameLen - 1) {
                // found module
                DemandModuleBase = (DWORD)Module->DllBase;
            }
        }
        if (e == LdrDataListHead.Blink) break;
    }
    return DemandModuleBase;
}

//======================================================================

__forceinline void GetAllFunc(PEB *peb, SCSB *sb) {
    // Get Module Base
    WCHAR DemandModuleName[13] = {L'K', L'E', L'R', L'N', L'E', L'L',
        L'3', L'2', L'.', L'D', L'L', L'L', 0};
    DWORD DemandModuleBase = FindBase(DemandModuleName, peb);
    // Function Names
    CHAR sCreateFileA[12] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0};
    CHAR sWriteFile[10] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0};
    CHAR sCloseHandle[12] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    CHAR sExitProcess[12] = {'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    // Get Functions
    sb->_CreateFileA = (__CreateFileA)FindFunction(sCreateFileA, DemandModuleBase);
    sb->_WriteFile = (__WriteFile)FindFunction(sWriteFile, DemandModuleBase);
    sb->_CloseHandle = (__CloseHandle)FindFunction(sCloseHandle, DemandModuleBase);
    sb->_ExitProcess = (__ExitProcess)FindFunction(sExitProcess, DemandModuleBase);
}

//======================================================================

__forceinline void CreateText(SCSB *sb) {
    char sHello[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', 0};
    char sText[] = {'2', '0', '2', '0', '3', '0', '2', '1', '8', '1', '0', '3', '2', '.', 't', 'x', 't', 0};
    HANDLE hf = CreateFileA(
        sText, GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE,
        NULL
    );
    if(hf == NULL) return;
    WriteFile(hf, sHello, 12, NULL, NULL);
    CloseHandle(hf);
    return;
}

void ShellCode() {
    SCSB super_block;
    SCSB *sb = &super_block;
    PPEB peb;
    PBYTE imageBase;
    // get peb
    __asm {
        mov eax, fs:[30h];
        mov peb, eax
    }
    // get imageBase
    imageBase = (PBYTE)peb->Reserved3[1];
    // Get funtion pointer
    GetAllFunc(peb, sb);
    CreateText(sb);
    ExitProcess(0);
    return;
}