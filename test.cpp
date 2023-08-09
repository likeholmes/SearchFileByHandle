#include <stdio.h>
#include <locale.h>
#include <tchar.h>
#include <strsafe.h>

#include "ntdll.h"

#define XP_FILETYPE 28
#define VISTA_FILETYPE 25
#define WIN10_FILETYPE 40

#define FILETYPE WIN10_FILETYPE

#pragma comment(lib, "ntdll.lib")

typedef struct _SYSTEM_HANDLE_INFO
{
    DWORD    dwProcessId;
    BYTE     bObjectType;
    BYTE     bFlags;
    WORD     wValue;
    PVOID    pAddress;
    DWORD    GrantedAccess;
}
SYSTEM_HANDLE_INFO, * PSYSTEM_HANDLE_INFO;

void PrintHandleInfo(const WCHAR* path, HANDLE handle)
{
    
    wprintf(L"Handle: %p, Type: %ld, Path: %s\n", handle, GetFileType(handle), path);
}

void FindFile(const TCHAR* file)
{
    // 获取系统中所有句柄信息
    ULONG size = 0;
    ULONG bufferSize = 0;
    ULONG handleCount = 0;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, NULL, 0, &bufferSize);

    do {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, bufferSize);
        if (handleInfo == NULL)
        {
            printf("HeapAlloc failed, error code: %u\n", GetLastError());
            return;
        }
        size = bufferSize;
        status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, size, &bufferSize);
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
        if (handle.ObjectTypeIndex != FILETYPE)//on xp is 28
            continue;

        SYSTEM_HANDLE_INFO handle2;
        CopyMemory(&handle2, &handle, sizeof(handle2));

        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle2.dwProcessId);
        if (hProcess == NULL)
        {
            //printf("OpenProcess failed, error code: %u\n", GetLastError());
            continue;
        }

        HANDLE hDupHandle;
        if (DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDupHandle, FILE_MAP_READ, FALSE, 0))
        {
            // 查询句柄所对应的对象信息
            CHAR* handleTableInfo = (CHAR*)handle.Object;
            WCHAR objectNameBuffer[MAX_PATH] = { 0 };
            ULONG returnLength = 0;
            
            if (GetFileType(hDupHandle) != 1)
                continue;

            status = NtQueryObject(hDupHandle, ObjectNameInformation, objectNameBuffer, sizeof(objectNameBuffer), &returnLength);
            if (status == STATUS_SUCCESS)
            {
                // 提取对象信息中的文件路径
                POBJECT_NAME_INFORMATION objectName = (POBJECT_NAME_INFORMATION)objectNameBuffer;
                if (wcsncmp(objectName->Name.Buffer, L"\\Device\\", wcslen(L"\\Device\\")) == 0)
                {
                    WCHAR filePath[MAX_PATH] = { 0 };
                    wcscpy_s(filePath, MAX_PATH, L"\\??\\");
                    wcsncat_s(filePath, MAX_PATH - wcslen(filePath), objectName->Name.Buffer + wcslen(L"\\Device\\"), objectName->Name.Length - wcslen(L"\\Device\\"));
                    LPCTSTR src = filePath + lstrlen(filePath) - lstrlen(file);
                    if (lstrcmpi(src, file) == 0)
                    {
                        PrintHandleInfo(filePath, hDupHandle);
                    }
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
