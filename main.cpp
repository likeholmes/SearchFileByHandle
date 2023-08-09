#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <locale.h>
#include <tchar.h>
#include <strsafe.h>
#include <Psapi.h>

#define SystemHandleInformation 0x10
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS 0x00000000

#define XP_FILETYPE 28
#define VISTA_FILETYPE 25
#define WIN10_FILETYPE 40

#define FILETYPE WIN10_FILETYPE

#pragma comment(lib, "ntdll.lib")

//typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
//    USHORT UniqueProcessId;
//    USHORT CreatorBackTraceIndex;
//    UCHAR ObjectTypeIndex;
//    UCHAR HandleAttributes;
//    USHORT HandleValue;
//    PVOID Object;
//    ULONG GrantedAccess;
//} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE
{
    DWORD    dwProcessId;
    BYTE     bObjectType;
    BYTE     bFlags;
    WORD     wValue;
    PVOID    pAddress;
    DWORD    GrantedAccess;
}
SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* PNT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _HANDLE_MAP {
    DWORD    dwProcessId;
    DWORD    nHandles;
    WORD     handleValue[1];
} SYSTEM_HANDLE_MAP;


BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR * pszFilename, DWORD maxBuffer)
{
    BOOL bSuccess = FALSE;
    HANDLE hFileMap;
    const DWORD BUFSIZE = 4028;

    // Get the file size.
    //DWORD dwFileSizeHi = 0;
    //DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    //if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
    //{
    //    _tprintf(TEXT("Cannot map a file with a length of zero.\n"));
    //    return FALSE;
    //}

    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL);

    if (hFileMap)
    {
        // Create a file mapping to get the file name.
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem)
        {
            if (GetMappedFileName(GetCurrentProcess(),
                pMem,
                pszFilename,
                MAX_PATH))
            {

                // Translate path with device name to drive letters.
                TCHAR szTemp[BUFSIZE];
                szTemp[0] = '\0';

                if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
                {
                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;

                    do
                    {
                        // Copy the drive letter to the template string
                        *szDrive = *p;

                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH))
                        {
                            size_t uNameLen = _tcslen(szName);

                            if (uNameLen < MAX_PATH)
                            {
                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                                    && *(pszFilename + uNameLen) == _T('\\');

                                if (bFound)
                                {
                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile,
                                        MAX_PATH,
                                        TEXT("%s%s"),
                                        szDrive,
                                        pszFilename + uNameLen);
                                    StringCchCopyN(pszFilename, maxBuffer, szTempFile, _tcslen(szTempFile));
                                    
                                }
                            }
                        }

                        // Go to the next NULL character.
                        while (*p++);
                    } while (!bFound && *p); // end of string
                }
            }
            bSuccess = TRUE;
            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMap);
    }
    else {
        DWORD err = GetLastError();
        printf("CreateFileMapping GetLastError:%ld\n", err);
    }

    
    return(bSuccess);
}

void PrintHandleInfo(const WCHAR* path, HANDLE handle)
{
    wprintf(L"Handle: %p, Path: %s\n", handle, path);
}

void FindFile(const TCHAR *file)
{
    // 获取 NtQuerySystemInformation 函数地址
    PNT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
        GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL)
    {
        printf("GetProcAddress failed, error code: %u\n", GetLastError());
        return;
    }

    // 获取系统中所有句柄信息
    ULONG size = 0;
    ULONG bufferSize = 0;
    ULONG handleCount = 0;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, NULL, 0, &bufferSize);

    do {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, bufferSize);
        if (handleInfo == NULL)
        {
            printf("HeapAlloc failed, error code: %u\n", GetLastError());
            return;
        }
        size = bufferSize;
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, handleInfo, size, &bufferSize);
        if (!NT_SUCCESS(status))
        {
            if (STATUS_INFO_LENGTH_MISMATCH == status)
            {
                HeapFree(GetProcessHeap(), 0, handleInfo);
                size = size * 2;
                continue;
            }
            else
            {
                printf("ZwQuerySystemInformation() failed, error code: %u\n", status);
                HeapFree(GetProcessHeap(), 0, handleInfo);
                return;
            }
        }
        else
        {
            break;
        }
    } while (true);    
    
    handleCount = handleInfo->NumberOfHandles;
    // 获取指定进程打开的文件句柄信息
    for (ULONG i = 0; i < handleCount; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];

        if (handle.bObjectType != FILETYPE)//on xp is 28
            continue;

        if (handle.dwProcessId != 10616)
            continue;

        if (handle.wValue != 0x608)
            continue;

        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.dwProcessId);
        if (hProcess == NULL)
        {
            //printf("OpenProcess failed, error code: %u\n", GetLastError());
            continue;
        }

        HANDLE hDupHandle;
        if (DuplicateHandle(hProcess, (HANDLE)handle.wValue, GetCurrentProcess(), &hDupHandle, FILE_MAP_READ, FALSE, 0))
        {
            WCHAR fileName[MAX_PATH]{};
            if (GetFileNameFromHandle(hDupHandle, fileName, MAX_PATH))
            {
                LPCTSTR src = fileName + lstrlen(fileName) - lstrlen(file);
                if (lstrcmpi(src, file) == 0)
                {
                    PrintHandleInfo(fileName, hDupHandle);
                }
                
            }
            
            CloseHandle(hDupHandle);
        }
        else
        {
            //printf("DuplicateHandle failed, error code: %u\n", GetLastError());
        }
        CloseHandle(hProcess);
    }

    HeapFree(GetProcessHeap(), 0, handleInfo);
}

int _tmain(int argc, _TCHAR* argv[])
{
    setlocale(LC_ALL, "chs");
    WCHAR buffer[4028];

    FindFile(L"docx");

    return 0;
}
