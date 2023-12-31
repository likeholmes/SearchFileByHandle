#include <stdio.h>
#include <locale.h>
#include <tchar.h>
#include <strsafe.h>

#include "ntdll.h"
#include <Windows.h>

#define XP_FILETYPE 28
#define VISTA_FILETYPE 25
#define WIN10_FILETYPE 37
#define WIN11_FILETYPE 40

#define FILETYPE WIN11_FILETYPE

#pragma comment(lib, "ntdll.lib")


void PrintHandleInfo(const WCHAR* path, HANDLE handle)
{
    
    wprintf(L"Handle: %p, Type: %ld, Path: %s\n", handle, GetFileType(handle), path);
}

NTSTATUS GetHandlesByProcessID()
{
    union {
        PVOID buf;
        PSYSTEM_HANDLE_INFORMATION_EX pshti;
    };

    NTSTATUS status;
    ULONG ReturnLength = 1024;//not reasonable value for start query,but let be
    ULONG UniqueProcessId = GetCurrentProcessId();
    do
    {
        status = STATUS_INSUFFICIENT_RESOURCES;

        if (buf = new BYTE[ReturnLength])
        {
            if (0 <= (status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, ReturnLength, &ReturnLength)))
            {
                if (ULONG_PTR NumberOfHandles = pshti->NumberOfHandles)
                {
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* Handles = pshti->Handles;
                    do
                    {
                        if (Handles->UniqueProcessId == UniqueProcessId)
                        {
                            //DbgPrint("%u, %p\n", Handles->ObjectTypeIndex, Handles->HandleValue);
                        }
                    } while (Handles++, --NumberOfHandles);
                }
            }

            delete buf;
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    return status;
}

void FindFile(const TCHAR* file)
{
    // 获取系统中所有句柄信息
    ULONG size = 0;
    ULONG bufferSize = 0;
    ULONG handleCount = 0;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;

    NTSTATUS status = NtQuerySystemInformation(SystemExtendedHandleInformation, NULL, 0, &bufferSize);

    do {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(GetProcessHeap(), 0, bufferSize);
        if (handleInfo == NULL)
        {
            printf("HeapAlloc failed, error code: %u\n", GetLastError());
            return;
        }
        size = bufferSize;
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, size, &bufferSize);
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
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = handleInfo->Handles[i];
        //if (handle.ObjectTypeIndex != FILETYPE)//on xp is 28
        //    continue;

        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId);
        if (hProcess == NULL)
        {
            //printf("OpenProcess failed, error code: %u\n", GetLastError());
            continue;
        }

        HANDLE hDupHandle;
        // docx可以，但会过滤掉pdf//if (DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDupHandle, FILE_MAP_READ, FALSE, 0))
        if (DuplicateHandle(hProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            // 查询句柄所对应的对象信息
            CHAR* handleTableInfo = (CHAR*)handle.Object;
            WCHAR objectNameBuffer[MAX_PATH] = { 0 };
            ULONG returnLength = 0;
            
            //if (GetFileType(hDupHandle) != 1) // 判断句柄是否为当前磁盘文件
            //    continue;

            // 使用CreateFileMapping打开失败的，过滤掉一些无效且打开巨慢的句柄
            HANDLE hFileMap = CreateFileMapping(hDupHandle, NULL, PAGE_READONLY, 0, 0, NULL);
            if (GetLastError() == 193) // %1 不是有效的 Win32 应用程序。可能代表句柄是无效的
                continue;
            if (hFileMap)
                CloseHandle(hFileMap);

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
    //GetHandlesByProcessID();
    FindFile(L"docx");

    return 0;
}
