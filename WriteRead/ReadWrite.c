#pragma once
#include <ntifs.h>
#include "PeTools.h"

/*
1.��ȡ����ģ��
2.��д
3.����ģ��
4.Զ��call
5.��������
*/




VOID UnloadDriver(PDRIVER_OBJECT obj) {
	ComUnloadCommmunication();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT obj,PUNICODE_STRING reg){
	ComInitCommmunication();

	//ULONG64 buf = 0;
	//ULONG64 begin = 0;
	//ULONG64 end = 0;
	//KeQueryTickCount(&begin);
	//for (ULONG64 i = 0; i < 1000000; i++)
	//{
	//	MmReadProcessMemory_VirBypass(1264, 0x100000000, &buf, 8);
	//}
	//KeQueryTickCount(&end);
	//DbgPrintEx(77, 0, "%10x cost %d s\r\n", buf,end - begin);
	//DbgBreakPoint();
	//PsVirtualByPass("on");
	//FcProtectProcessByGlobalHandleTable(2656,0);
	//FsDeleteFile((char*)"C:\\Users\\ssh\\Desktop\\WriteRead.sys");
	//if (FcProtectProcessByGlobalHandleTable(7472))
	//{
	//	DbgPrintEx(77, 0, "success!\r\n");
	//}
	//DbgPrintEx(77, 0, "error!\r\n");
	//STATUS_INVALID_ADDRESS
	//obj->DriverUnload = UnloadDriver;
	return STATUS_SUCCESS;
}