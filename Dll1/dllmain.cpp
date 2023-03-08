// dllmain.cpp : 定义 DLL 应用程序的入口点。
#pragma once
#include "comm.h"
#include "km.h"



int main(int argc, char* argv[])
{
    //if (InitCom())
    //{
    //    printf("InitCom\r\n");
    //}
    //if (TestCom())
    //{
    //    printf("TestCom\r\n");
    //}
    //ULONG64 begin = GetTickCount();
    //ULONG64 a = 0;
    //for (ULONG64 i = 0; i < 1000000; i++)
    //{
    //    ReadProcMemory(1888, 0x100000000, (ULONG64)&a, 8, 3);
    //}
    //ULONG64 end = GetTickCount();
    //printf("%d\r\n", end - begin);
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS,FALSE,2132);
    printf("handle = %d\r\n", h);
    ULONG64 base = 0X60A0000;
    PVOID ret = VirtualAllocEx(h,(PVOID)base, 0x1000000, MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    printf("%llx\r\n", ret);

    system("pause");
	return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

