#pragma once 
#include "PeTools.h"

RTL_OSVERSIONINFOEXW VER_INFO = { 0 };


FORCEINLINE
BOOLEAN
RemoveEntryList32(
	_In_ PLIST_ENTRY32 Entry
)

{

	PLIST_ENTRY32 PrevEntry;
	PLIST_ENTRY32 NextEntry;

	NextEntry = Entry->Flink;
	PrevEntry = Entry->Blink;
	if (!NextEntry || !PrevEntry)
	{
		return FALSE;
	}
	//if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {
	//	FatalListEntryError((PVOID)PrevEntry,
	//		(PVOID)Entry,
	//		(PVOID)NextEntry);
	//}

	PrevEntry->Flink = NextEntry;
	NextEntry->Blink = PrevEntry;
	return (BOOLEAN)(PrevEntry == NextEntry);
}

FORCEINLINE
BOOLEAN
RemoveEntryList64(
	_In_ PLIST_ENTRY Entry
)

{

	PLIST_ENTRY PrevEntry;
	PLIST_ENTRY NextEntry;

	NextEntry = Entry->Flink;
	PrevEntry = Entry->Blink;
	if (!NextEntry || !PrevEntry)
	{
		return FALSE;
	}
	if ((NextEntry->Blink != Entry) || (PrevEntry->Flink != Entry)) {
		FatalListEntryError((PVOID)PrevEntry,
			(PVOID)Entry,
			(PVOID)NextEntry);
	}

	PrevEntry->Flink = NextEntry;
	NextEntry->Blink = PrevEntry;
	return (BOOLEAN)(PrevEntry == NextEntry);
}


/*-----------------------------PE部分----------------------------------------*/
/*拉伸PE镜像*/
PUCHAR PeFileToImage(PUCHAR ptr) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)ptr);
	ULONG SectionNum = nt->FileHeader.NumberOfSections;
	ULONG SizeOfImage = nt->OptionalHeader.SizeOfImage;
	PUCHAR imagePtr = ExAllocatePool(NonPagedPool,SizeOfImage);
	RtlZeroMemory(imagePtr, SizeOfImage);

	RtlCopyMemory(imagePtr, ptr, nt->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER SectionBase = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < SectionNum;i++) {
		RtlCopyMemory((ULONG)imagePtr + SectionBase->VirtualAddress, (ULONG)ptr + SectionBase->PointerToRawData, SectionBase->SizeOfRawData);
		SectionBase++;
	}

	return imagePtr;
}

/*根据指定区段名取区段相对偏移*/
ULONG PeGetSectionOffsetByName(PUCHAR ptr, PUCHAR name,PULONG size) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)ptr);
	ULONG SectionNum = nt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionBase = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < SectionNum; i++) {
		if (!strcmp(SectionBase->Name,name))
		{
			*size = SectionBase->SizeOfRawData;
			return SectionBase->VirtualAddress;
		}
		SectionBase++;
	}

	return NULL;
}

/*修复重定位*/
VOID PeFixReloc(PUCHAR ptr,ULONG isNeedFixCookie) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)ptr);
	PIMAGE_DATA_DIRECTORY pReloc = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ULONG ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_BASE_RELOCATION relocAddr = (PIMAGE_BASE_RELOCATION)((ULONG)ptr + pReloc->VirtualAddress);
	
	while (relocAddr->VirtualAddress && relocAddr->SizeOfBlock) {
		
		PUCHAR RelocBase = (PUCHAR)((ULONG)ptr + relocAddr->VirtualAddress);
		ULONG BlockNum = relocAddr->SizeOfBlock / 2 - 4;
		for (ULONG i = 0; i < BlockNum;i++) {
			ULONG Block = *(PUSHORT)((ULONG)relocAddr + 8 + 2 * i);
			ULONG high4 = Block & 0xF000;
			ULONG low12 = Block & 0xFFF;
			PULONG RelocAddr = (PULONG)((ULONG)RelocBase + low12);
			if (high4 == 0x3000) {
				*RelocAddr = *RelocAddr - ImageBase + (ULONG)ptr;
				PULONG cookiePtr = (PULONG)(*RelocAddr);
				if (isNeedFixCookie && *cookiePtr == 0xB40E64E) {
					*cookiePtr = 0x65083911;
				}
			}
		}
		relocAddr = (PIMAGE_BASE_RELOCATION)((ULONG)relocAddr + relocAddr->SizeOfBlock);
	}
}

/*修复导入表*/
VOID PeFixImport(PUCHAR ptr) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)ptr);
	ULONG ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY pImport = &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	PIMAGE_IMPORT_DESCRIPTOR importDes = pImport->VirtualAddress + ptr;

	while (importDes->Name)
	{
		ULONG ModuleSize = 0;
		ULONG_PTR base = KrGetKernelModuleBase(importDes->Name+ptr, &ModuleSize);
		PULONG pImData = (PULONG)(importDes->FirstThunk + ptr);
		
		while (*pImData)
		{
			PIMAGE_IMPORT_BY_NAME FuncName = *pImData + ptr;
			ULONG FuncAddr = (ULONG)PeGetExportFuncAddr64(base, FuncName->Name);
			*pImData = FuncAddr;
			pImData++;
		}
		importDes++;
	}
}
/*获取导出函数地址*/
//ULONG64 PeGetExportFuncAddr(char* pData, char* funcName)
//{
//	DbgBreakPoint();
//	PIMAGE_DOS_HEADER pHead = (PIMAGE_DOS_HEADER)pData;
//	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pHead->e_lfanew);
//	int numberRvaAndSize = pNt->OptionalHeader.NumberOfRvaAndSizes;
//	PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)&pNt->OptionalHeader.DataDirectory[0];
//	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pData + pDir->VirtualAddress);
//	ULONG64 funcAddr = 0;
//	for (int i = 0; i < pExport->NumberOfNames; i++)
//	{
//		int* funcAddress = pData + pExport->AddressOfFunctions;
//		int* names = pData + pExport->AddressOfNames;
//		short* fh = pData + pExport->AddressOfNameOrdinals;
//		int index = -1;
//		char* name = pData + names[i];
//		DbgBreakPoint();
//		if (!MmIsAddressValid(name))
//		{
//			continue;
//		}
//		if (strcmp(name, funcName) == 0)
//		{
//			index = fh[i];
//		}
//
//
//
//		if (index != -1)
//		{
//			funcAddr = pData + funcAddress[index];
//			break;
//		}
//
//
//	}
//
//	if (!funcAddr)
//	{
//		KdPrint(("没有找到函数%s\r\n", funcName));
//
//	}
//	else
//	{
//		KdPrint(("找到函数%s addr %p\r\n", funcName, funcAddr));
//	}
//
//
//	return funcAddr;
//}

PUCHAR PeGetExportFuncAddr64(PUCHAR base,PUCHAR funcName) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((ULONG64)base+dos->e_lfanew);
	ULONG64 ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY pExport = &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY pExDir = pExport->VirtualAddress + base;
	ULONG64 NumberOfFuncs = pExDir->NumberOfFunctions;
	ULONG64 NumberOfNames = pExDir->NumberOfNames;
	PULONG AddrOfFuncs = pExDir->AddressOfFunctions + base;
	PULONG AddrOfNames = pExDir->AddressOfNames + base;
	PUSHORT AddrOfNameOrd = pExDir->AddressOfNameOrdinals + base;

	for (ULONG64 i = 0; i < NumberOfNames; i++)
	{
		PUCHAR preName = AddrOfNames[i] + base;
		if (!MmIsAddressValid(preName))
		{
			return -1;
		}
		if (!strcmp(funcName, preName)) {
			return AddrOfFuncs[AddrOfNameOrd[i]] + base;
		}
	}
	return NULL;
}
PUCHAR PeGetExportFuncAddr32(PUCHAR base, PUCHAR funcName) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)((ULONG64)base + dos->e_lfanew);
	ULONG64 ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY pExport = &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY pExDir = pExport->VirtualAddress + base;
	ULONG64 NumberOfFuncs = pExDir->NumberOfFunctions;
	ULONG64 NumberOfNames = pExDir->NumberOfNames;
	PULONG AddrOfFuncs = pExDir->AddressOfFunctions + base;
	PULONG AddrOfNames = pExDir->AddressOfNames + base;
	PUSHORT AddrOfNameOrd = pExDir->AddressOfNameOrdinals + base;

	for (ULONG64 i = 0; i < NumberOfNames; i++)
	{
		PUCHAR preName = AddrOfNames[i] + base;
		if (!MmIsAddressValid(preName))
		{
			return -1;
		}
		if (!strcmp(funcName, preName)) {
			return AddrOfFuncs[AddrOfNameOrd[i]] + base;
		}
	}
	return NULL;
}

/*取入口点地址*/
PULONG PeGetEntryPoint(PCHAR base) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)base);
	return nt->OptionalHeader.AddressOfEntryPoint + base;
}

/*清空PE头*/
VOID PeCleanPeHeader(PCHAR base) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)base);
	RtlZeroMemory(base,nt->OptionalHeader.SizeOfHeaders);
}










/*------------------------------------------内核部分------------------------------------------*/




/*取驱动模块基址与大小*/
ULONG_PTR KrGetKernelModuleBase(PUCHAR moduleName, PULONG pModuleSize) {
	RTL_PROCESS_MODULES SysModules = { 0 };
	PRTL_PROCESS_MODULES pModules = &SysModules;
	ULONG64 SystemInformationLength = 0;


	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pModules, sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		pModules = ExAllocatePool(NonPagedPool, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		RtlZeroMemory(pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pModules);
			return 0;
		}
	}

	if (!strcmp("ntoskrnl.exe", moduleName) || !strcmp("ntkrnlpa.exe.exe", moduleName)) {
		*pModuleSize = pModules->Modules[0].ImageSize;
		ULONG_PTR ret = pModules->Modules[0].ImageBase;
		if (SystemInformationLength) {
			ExFreePool(pModules);
		}
		return ret;
	}

	for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
		if (strstr(pModules->Modules[i].FullPathName, moduleName)) {
			*pModuleSize = pModules->Modules[i].ImageSize;
			ULONG_PTR ret = pModules->Modules[i].ImageBase;
			if (SystemInformationLength) {
				ExFreePool(pModules);
			}
			return ret;
		}
	}
	if (SystemInformationLength) {
		ExFreePool(pModules);
	}
	return 0;
}



/*特征码搜寻  AC??AC 格式*/
PUCHAR MmFindAddrBySignCode(PUCHAR startAddr,PUCHAR sign,ULONG len) {
	ULONG signArr[0x100]  = { 0 };
	ULONG index = 0;
	ULONG signBytes = strlen(sign) / 2;
	for (index = 0; index < signBytes; index++)
	{
		ULONG signIndex = index * 2;
		char temp1 = sign[signIndex];
		char temp2 = sign[signIndex +1];
		ULONG high = 0;
		ULONG low = 0;
		if (temp1=='?'&& temp2 == '?')
		{
			signArr[index] = 999;
			continue;
		}
		if (temp1<'0' || temp1>'F'|| temp2 < '0' || temp2>'F')
		{
			return NULL;
		}
		if (temp1>='0'&&temp1<='9')
		{
			high = temp1 - 48;
		}
		if (temp1 >= 'A' && temp1 <= 'F')
		{
			high = temp1 - 65+10;
		}
		if (temp2 >= '0' && temp2 <= '9')
		{
			low = temp2 - 48;
		}
		if (temp2 >= 'A' && temp2 <= 'F')
		{
			low = temp2 - 65 + 10;
		}
		signArr[index] = high*16+low;
	}
	PUCHAR currentPtr = startAddr;
	ULONG rightBytes = 0;
	while((currentPtr - startAddr)<=(len - signBytes)){
		for (ULONG i = 0; i < signBytes; i++)
		{
			if (signArr[i]==999) {
				rightBytes++;
				continue;
			}
			if (!MmIsAddressValid(currentPtr+i))
			{
				currentPtr = (PUCHAR)((UCHAR)currentPtr&0xFFFFF000 + 0x1000);
				rightBytes = 0;
				break;
			}
			if (signArr[i]!= (UCHAR)*(currentPtr + i))
			{
				currentPtr = currentPtr + i + 1;
				rightBytes = 0;
				break;
			}
			rightBytes++;
		}
		if (rightBytes == signBytes)
		{
			return currentPtr;
		}
	}
	return NULL;
}


/*全局句柄表二级指针 需要再取一次值*/
PUCHAR KrGetGlobalHandleTablePointer() {
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");
	PUCHAR pPsLookupProcessByProcessId = (PUCHAR)MmGetSystemRoutineAddress(&name);
	if (!pPsLookupProcessByProcessId)
	{
		return NULL;
	}
	PUCHAR temp = NULL;
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		//win7
		temp = (PUCHAR)MmFindAddrBySignCode(pPsLookupProcessByProcessId, "498B??488B??488B??????????E8", 0x200);
		if (!temp)
		{
			return NULL;
		}
		return *(PLONG)(temp + 9) + temp+9+4;
	}
	else if (VER_INFO.dwBuildNumber == 22000)
	{
		//WIN11
		PUCHAR temp = (PUCHAR)MmFindAddrBySignCode(pPsLookupProcessByProcessId, "66FF8F????????B2??E8", 0x200);
		if (!temp)
		{
			return NULL;
		}
		PUCHAR pPspReferenceCidTableEntry = *(PLONG)(temp + 10) + temp + 14;
		temp = (PUCHAR)MmFindAddrBySignCode(pPspReferenceCidTableEntry, "4C8B35", 0x200);
		if (!temp)
		{
			return NULL;
		}

		return *(PLONG)(temp + 3) + temp + 7;
	}
	else
	{
		//WIN10
		PUCHAR temp = (PUCHAR)MmFindAddrBySignCode(pPsLookupProcessByProcessId, "66FF8F????????B2??E8", 0x200);
		if (!temp)
		{
			return NULL;
		}
		PUCHAR pPspReferenceCidTableEntry = *(PLONG)(temp + 10) + temp + 14;
		temp = (PUCHAR)MmFindAddrBySignCode(pPspReferenceCidTableEntry, "488B05", 0x200);
		if (!temp)
		{
			return NULL;
		}
		
		return *(PLONG)(temp + 3) + temp + 7;
	}
	return NULL;
}
/*ExpLookupHandleTableEntry函数地址*/
PUCHAR KrGetExpLookupHandleTableEntryAddr() {
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name,L"ExEnumHandleTable");
	PUCHAR pExEnumHandleTable = (PUCHAR)MmGetSystemRoutineAddress(&name);
	if (!pExEnumHandleTable)
	{
		return NULL;
	}
	PUCHAR temp = NULL;
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		//win7
		temp = (PUCHAR)MmFindAddrBySignCode(pExEnumHandleTable,"488B??498B??E8????????493B??74??4C39??75??",0x200);
		if (!temp)
		{
			return NULL;
		}
		return *(PLONG)(temp + 7) + temp + 11;
	}
	else if (VER_INFO.dwBuildNumber == 22000)
	{
		//WIN11
		temp = (PUCHAR)MmFindAddrBySignCode(pExEnumHandleTable, "4983????488B??498B??E8????????488B??EB", 0x200);
		if (!temp)
		{
			return NULL;
		}
		return *(PLONG)(temp + 11) + temp + 15;
	}
	else
	{
		temp = (PUCHAR)MmFindAddrBySignCode(pExEnumHandleTable, "4983????488B??498B??E8????????488B??E9", 0x200);
		if (!temp)
		{
			return NULL;
		}
		return *(PLONG)(temp + 11) + temp + 15;
		//WIN10
	}
	return NULL;
}
/*进程结构体中PID成员的偏移*/
ULONG KrGetPidOffset() {
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name, L"PsGetProcessId");
	PUCHAR pPsGetProcessId = (PUCHAR)MmGetSystemRoutineAddress(&name);
	if (!pPsGetProcessId)
	{
		return NULL;
	}
	PUCHAR temp = NULL;
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		//WIN7
		return *(PULONG)(pPsGetProcessId + 3);
	}
	else if (VER_INFO.dwBuildNumber == 22000)
	{
		//WIN11
		return *(PULONG)(pPsGetProcessId + 3);
	}
	else
	{
		//WIN10
		return *(PULONG)(pPsGetProcessId + 3);
	}
	return NULL;
}
/*进程结构体中PID成员的偏移*/
ULONG KrGetImageFileNameOffset() {
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name, L"PsGetProcessImageFileName");
	PUCHAR pPsGetProcessImageFileName = (PUCHAR)MmGetSystemRoutineAddress(&name);
	if (!pPsGetProcessImageFileName)
	{
		return NULL;
	}
	return *(PULONG)(pPsGetProcessImageFileName + 3);
}

/*在虚拟机中要摘除CreateProcess内核钩子*/
/*抹全局句柄表保护进程*/
BOOLEAN FcProtectProcessByGlobalHandleTable(ULONG64 pid,ULONG64 dstPid) {
	ULONG64 fakePid = 0;
	PUCHAR pExpLookupHandleTableEntry = KrGetExpLookupHandleTableEntryAddr();
	PUCHAR pGlobalHandleTable = KrGetGlobalHandleTablePointer();
	if (!pExpLookupHandleTableEntry || !pGlobalHandleTable)
	{
		return FALSE;
	}
	typedef PULONG64(NTAPI* MyExpLookupHandleTableEntry)(ULONG64 arg1, ULONG64 pid);
	MyExpLookupHandleTableEntry func = (MyExpLookupHandleTableEntry)pExpLookupHandleTableEntry;
	PULONG64 handle = func(*(PULONG64)pGlobalHandleTable, pid);
	if (dstPid)
	{
		fakePid = dstPid;
	}
	else {
		fakePid = PsGetPidByName("explorer.exe");
	}
	if (!fakePid)
	{
		return FALSE;
	}
	PULONG64 fakeHandle = func(*(PULONG64)pGlobalHandleTable, fakePid);
	if (handle && fakeHandle)
	{
		//PEPROCESS proc = NULL;
		//PsLookupProcessByProcessId(pid, &proc);
		//ULONG offset = KrGetPidOffset();
		//*(PULONG64)((PUCHAR)proc + offset) = 0;
		if (!HideProcessEx(pid, fakePid))
		{
			return FALSE;
		}
		*handle = *fakeHandle;
		*(handle + 1) = *(fakeHandle+1);
		//*handle = 0;
		//*(handle + 1) = 0;
		//ObDereferenceObject(proc);
		//if (strong)
		//{
			//PLIST_ENTRY entry = (PUCHAR)proc + KrGetPidOffset() + 8;
			//RemoveEntryList(entry);
			//entry->Blink = entry;
			//entry->Flink = entry;
		//}
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
/*重设私有句柄表防降权*/
BOOLEAN NTAPI FcResetHandleLevel(PHANDLE_TABLE_ENTRY entry,HANDLE handle, PEPROCESS param) {
	PUCHAR currentProc = (PUCHAR)(entry->Object)+0x18;
	PUCHAR obj = (PUCHAR)(entry->Object);
	if (*(obj+0xC)!=0x7)
	{
		return FALSE;
	}
	if (currentProc == param || 
		*(PULONG)(currentProc + 0xb4) == *(PULONG)((PUCHAR)param + 0xb4) ||	//进程ID
		*(PULONG)(currentProc + 0x18) == *(PULONG)((PUCHAR)param + 0x18) || //进程CR3
		!strcmp(currentProc + 0x16c, (PUCHAR)param + 0x16c))	
	{
		entry->GrantedAccess &= ~(0x0020 | 0x0010);
	}
	return FALSE;
}
/*内核Sleep*/
VOID CpMySleepSec(LONGLONG time) {
	LARGE_INTEGER li = { 0 };	//时长结构。
	li.QuadPart = -10000 * 1000 * time;	//时间单位 负数代表相对时间  正数代表绝对时间。 5000代表5秒。 
	KeDelayExecutionThread(KernelMode, FALSE, &li);
}
VOID CpMySleepMin(LONGLONG time) {
	LARGE_INTEGER li = { 0 };	//时长结构。
	li.QuadPart = -10000 * time;	//时间单位 负数代表相对时间  正数代表绝对时间。 5000代表5秒。 
	KeDelayExecutionThread(KernelMode, FALSE, &li);
}

_PROCESS_PROTECT_SIGN = FALSE;
/*遍历其他进程私有句柄表保护指定进程句柄*/
VOID Thread_ProtectProcessHandle(_In_ PUCHAR proc) {
	
	while (_PROCESS_PROTECT_SIGN) {
		for (ULONG i = 0; i < 0x1000000; i+=4)
		{
			PEPROCESS currentProc = NULL;
			NTSTATUS sta = PsLookupProcessByProcessId(i, &currentProc);
			if (!NT_SUCCESS(sta))
			{
				continue;
			}
			PUCHAR pHandleTable = (PUCHAR)currentProc + 0xF4;
			if (!MmIsAddressValid(pHandleTable) || !MmIsAddressValid(*(PULONG)pHandleTable))
			{
				ObDereferenceObject(currentProc);
				DbgPrintEx(77,0,"%s\r\n", (PUCHAR)currentProc+0x16c);
				continue;
			}
			ExEnumHandleTable(*(PULONG)pHandleTable, FcResetHandleLevel, proc, NULL);
			ObDereferenceObject(currentProc);
		}
		CpMySleepSec(5);
	}
	
}
/*遍历其他进程私有句柄表保护指定进程句柄*/
BOOLEAN FcProtectProcessHandle(ULONG pid) {
	PEPROCESS dstProc = NULL;
	PHANDLE handle = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &dstProc);
	if (!NT_SUCCESS(ret))
	{
		return FALSE;
	}
	_PROCESS_PROTECT_SIGN = TRUE;
	NTSTATUS tRet = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, Thread_ProtectProcessHandle, dstProc);
	ObDereferenceObject(dstProc);
	if (NT_SUCCESS(tRet)) {
		return FALSE;
	}
	return TRUE;
}
/*结束遍历其他进程私有句柄表保护指定进程句柄*/
VOID FcEndProtectProcessHandle() {
	_PROCESS_PROTECT_SIGN = FALSE;
	CpMySleepSec(10);
}

PUCHAR newEproc = NULL;
/*更改私有句柄权限提权*/
BOOLEAN NTAPI Callback_ChangeHandleProc(PHANDLE_TABLE_ENTRY entry, HANDLE handle, PEPROCESS dstProc) {
	PUCHAR currentProc = (PUCHAR)(entry->Object) + 0x18;
	PUCHAR obj = (PUCHAR)(entry->Object);
	if (!newEproc)
	{
		return TRUE;
	}
	if (currentProc == dstProc ||
		*(PULONG)(currentProc + 0xb4) == *(PULONG)((PUCHAR)dstProc + 0xb4) ||	//进程ID
		*(PULONG)(currentProc + 0x18) == *(PULONG)((PUCHAR)dstProc + 0x18) || //进程CR3
		!strcmp(currentProc + 0x16c, (PUCHAR)dstProc + 0x16c))
	{
		entry->Object = newEproc;
		entry->GrantedAccess |= (0x0020 | 0x0010);
	}
	return FALSE;
}
/*复制Eprocess结构提权*/
BOOLEAN KrUpProcessHandleRWLevel(ULONG src,ULONG dst) {
	newEproc = (PUCHAR)ExAllocatePool(NonPagedPool, 0x500);
	if (!newEproc)
	{
		return FALSE;
	}
	memset(newEproc, 0, 0x500);

	PEPROCESS dstProc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(dst, &dstProc);
	if (!NT_SUCCESS(ret))
	{
		return FALSE;
	}
	memcpy(newEproc, (PUCHAR)dstProc-0x18,0x270);
	
	*(PULONG)((PUCHAR)newEproc +0x18+ 0xb4) = 0;
	*(PULONG)((PUCHAR)newEproc + 0x18 + 0x16c) = 0;

	ULONG oldCr3 = *(PULONG)((PUCHAR)dstProc + 0x18);
	PHYSICAL_ADDRESS cr3Phy = { 0 };
	cr3Phy.QuadPart = oldCr3;
	ULONG size = PAGE_SIZE;
	if (oldCr3 & 0xFFF)
	{
		size = 0x20;
	}
	PUCHAR oldCr3LineAddr = (PUCHAR)MmMapIoSpace(cr3Phy, size, MmNonCached);
	PUCHAR newCr3 = (PUCHAR)ExAllocatePool(NonPagedPool, size);
	memset(newCr3, 0, size);
	memcpy(newCr3, oldCr3LineAddr, size);
	PHYSICAL_ADDRESS newCr3Phy = MmGetPhysicalAddress(newCr3);
	*(PULONG)((PUCHAR)newEproc + 0x18*2) = newCr3Phy.LowPart;

	PEPROCESS srcProc = NULL;
	ret = PsLookupProcessByProcessId(src, &srcProc);
	if (!NT_SUCCESS(ret))
	{
		ObDereferenceObject(dstProc);
		return FALSE;
	}
	ExEnumHandleTable(*(PULONG)((PUCHAR)srcProc + 0xf4), Callback_ChangeHandleProc, dstProc, NULL);
	ObDereferenceObject(dstProc);
	ObDereferenceObject(srcProc);
	return TRUE;
}
/*从PEB链表中获取指定Wow64进程基址*/
ULONG_PTR KrFindWow64ModuleBaseFromPebByName(PPEB32 peb, char* moduleName) {
	if (!peb)
	{
		return NULL;
	}
	PPEB_LDR_DATA32 ldrData = (PPEB_LDR_DATA32)peb->Ldr;
	PLDR_DATA_TABLE_ENTRY32 begin = (PLDR_DATA_TABLE_ENTRY32)ldrData->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY32 next = (PLDR_DATA_TABLE_ENTRY32)begin;
	do
	{
		ANSI_STRING name = { 0 };
		UNICODE_STRING nameUni = { 0 };
		RtlInitAnsiString(&name, moduleName);
		RtlAnsiStringToUnicodeString(&nameUni, &name, TRUE);
		//DbgPrintEx(77, 0, "find a process:[%ls]\r\n", next->BaseDllName.Buffer);
		if (next->DllBase && wcscmp(nameUni.Buffer, next->BaseDllName.Buffer) == 0)
		{
			RtlFreeAnsiString(&nameUni);
			return next->DllBase;
		}
		next = (PLDR_DATA_TABLE_ENTRY32)next->InLoadOrderLinks.Flink;
		RtlFreeAnsiString(&nameUni);
	} while (begin != next && next);

}
/*从PEB链表中获取指定X64进程基址*/
ULONG_PTR KrFindX64ModuleBaseFromPebByName(PPEB peb64, char* moduleName) {
	if (!peb64)
	{
		return NULL;
	}
	PPEB_LDR_DATA64 ldrData = (PPEB_LDR_DATA64)(*(PULONG64)((ULONG64)peb64 + 0x18));
	PLDR_DATA_TABLE_ENTRY64 begin = (PLDR_DATA_TABLE_ENTRY64)ldrData->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY64 next = (PLDR_DATA_TABLE_ENTRY64)begin;
	do
	{
		ANSI_STRING name = { 0 };
		UNICODE_STRING nameUni = { 0 };

		RtlInitAnsiString(&name, moduleName);
		RtlAnsiStringToUnicodeString(&nameUni, &name, TRUE);
		if (next->DllBase && RtlCompareUnicodeString(&nameUni, &(next->BaseDllName), TRUE) == 0)
		{
			RtlFreeAnsiString(&nameUni);
			return next->DllBase;
		}
		next = (PLDR_DATA_TABLE_ENTRY64)next->InLoadOrderLinks.Flink;
		RtlFreeAnsiString(&nameUni);
	} while (begin != next && next);
	return NULL;
}

PPEB32 PsGetWow64ProcPeb32(PEPROCESS proc) {
	PPEB32 peb32 = NULL;
	if (VER_INFO.dwBuildNumber == 7601 || VER_INFO.dwBuildNumber == 7600)
	{
		peb32 = (PPEB32) * ((PULONG64)((PUCHAR)proc + 0x320));
	}
	else if (VER_INFO.dwBuildNumber == 22000) {
		ULONG64 tmp = *((((PULONG64)((PUCHAR)proc + 0x580))));
		if (tmp)
		{
			peb32 = (PPEB32) * (PULONG64)(tmp);
		}
	}
	else
	{
		ULONG64 tmp = *((((PULONG64)((PUCHAR)proc + 0x428))));
		if (tmp)
		{
			peb32 = (PPEB32) * (PULONG64)(tmp);
		}
	}
	return peb32;
}

PKTRAP_FRAME PsGetThreadTrapFrame(PUCHAR thread) {
	if (!thread || !MmIsAddressValid(thread))
	{
		return NULL;
	}
	/*if (VER_INFO.dwBuildNumber == 7601 || VER_INFO.dwBuildNumber == 7600)
	{
		return *(PULONG64)(thread + 0x1D8);
	}
	else {
		return *(PULONG64)(thread + 0x90);
	}*/
	return *(PULONG64)(thread + 0x28) - sizeof(KTRAP_FRAME);
}

PTEB64 PsGetThreadTeb64(PUCHAR thread) {
	if (!thread || !MmIsAddressValid(thread))
	{
		return NULL;
	}
	if (VER_INFO.dwBuildNumber == 7601 || VER_INFO.dwBuildNumber == 7600)
	{
		return *(PULONG64)(thread + 0xB8);
	}
	else {
		return *(PULONG64)(thread + 0xF0);
	}
}

PEPROCESS PsGetThreadApcProcess(PETHREAD thread) {
	if (!thread || !MmIsAddressValid(thread))
	{
		return NULL;
	}
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		return *(PULONG64)((PUCHAR)thread + 0x50 + 0x20);
	}
	else 
	{
		return *(PULONG64)((PUCHAR)thread + 0x98 + 0x20);
	}
}


/*根据模块名取模块基址*/
ULONG_PTR KrGetProcModuleBaseByName(ULONG pid,char* moduleName) {
	if (moduleName == NULL)
	{
		return NULL;
	}
	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return 0;
	}
	KAPC_STATE apc = {0};
	char* name = (char*)ExAllocatePool(NonPagedPool,0x200);
	strcpy(name, moduleName);
	KeStackAttachProcess(proc,&apc);

	ULONG_PTR base = NULL;
	PPEB32 peb32 = PsGetWow64ProcPeb32(proc);
	if (peb32)
	{
		//wow64	
		base = KrFindWow64ModuleBaseFromPebByName(peb32, name);
	}
	else {
		//X64
		PPEB peb64 = (PPEB)PsGetProcessPeb(proc);
		base = KrFindX64ModuleBaseFromPebByName(peb64, name);
	}
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(proc);
	return base;
}

AttributeInformationCallBack oldExpDisQueryAttributeInformation = 0;
AttributeInformationCallBack oldExpDisSetAttributeInformation = 0;
ULONG64 _PACKAGE_SIGN = 0x65083911;

NTSTATUS  CallBack_ExpDisQueryAttributeInformation(ULONG64 handle, ULONG64 param) {
	PComPackage pack = (PComPackage)param;
	if (pack->sign == _PACKAGE_SIGN)
	{
		return ComHandlePackage(pack);
	}
	else
	{
		if (oldExpDisQueryAttributeInformation)
		{
			return oldExpDisQueryAttributeInformation(handle, param);
		}
	}

}
NTSTATUS  CallBack_ExpDisSetAttributeInformation(ULONG64 handle, ULONG64 param) {
	PComPackage pack = (PComPackage)param;
	if (pack->sign == _PACKAGE_SIGN)
	{
		ComHandlePackage(pack);
	}
	else
	{
		if (oldExpDisSetAttributeInformation)
		{
			return oldExpDisSetAttributeInformation(handle, param);
		}
	}
}
BOOLEAN ComInitWin7Commmunication() {
	UNICODE_STRING Str_ExRegisterAttributeInformationCallback = { 0 };
	RtlInitUnicodeString(&Str_ExRegisterAttributeInformationCallback, L"ExRegisterAttributeInformationCallback");
	PUCHAR pExRegisterAttributeInformationCallback = (PUCHAR)MmGetSystemRoutineAddress(&Str_ExRegisterAttributeInformationCallback);
	PULONG64 pExpDisQueryAttributeInformation = (PULONG64)(*(PULONG)(pExRegisterAttributeInformationCallback + 16) + pExRegisterAttributeInformationCallback + 16 + 4);
	oldExpDisQueryAttributeInformation = (AttributeInformationCallBack)pExpDisQueryAttributeInformation[0];
	oldExpDisSetAttributeInformation = (AttributeInformationCallBack)pExpDisQueryAttributeInformation[1];
	pExpDisQueryAttributeInformation[0] = 0;
	pExpDisQueryAttributeInformation[1] = 0;
	funcExRegisterAttributeInformationCallback ExRegisterAttributeInformationCallback = (funcExRegisterAttributeInformationCallback)pExRegisterAttributeInformationCallback;
	RegisterAttributeInformationCallback callBack = { 0 };
	callBack.ExpDisQueryAttributeInformation = CallBack_ExpDisQueryAttributeInformation;
	callBack.ExpDisSetAttributeInformation = CallBack_ExpDisSetAttributeInformation;
	return ExRegisterAttributeInformationCallback(&callBack);
}

VOID ComUnloadWin7Communication() {
	UNICODE_STRING Str_ExRegisterAttributeInformationCallback = { 0 };
	RtlInitUnicodeString(&Str_ExRegisterAttributeInformationCallback, L"ExRegisterAttributeInformationCallback");
	PUCHAR pExRegisterAttributeInformationCallback = (PUCHAR)MmGetSystemRoutineAddress(&Str_ExRegisterAttributeInformationCallback);
	PULONG64 pExpDisQueryAttributeInformation = (PULONG64)(*(PULONG)(pExRegisterAttributeInformationCallback + 16) + pExRegisterAttributeInformationCallback + 16 + 4);
	pExpDisQueryAttributeInformation[0] = oldExpDisQueryAttributeInformation;
	pExpDisQueryAttributeInformation[1] = oldExpDisSetAttributeInformation;
}

Win10_off_140401C70CallBack oldCallBack_Win10_off_140401C70 = NULL;
NTSTATUS  CallBack_Win10_off_140401C70(PUCHAR p1, PUCHAR p2, PUCHAR p3) {
	PComPackage pack = (PComPackage)p1;
	if (pack->sign == _PACKAGE_SIGN)
	{
		ComHandlePackage(pack);
	}
	else
	{
		if (oldCallBack_Win10_off_140401C70)
		{
			return oldCallBack_Win10_off_140401C70(p1, p2,p3);
		}
	}

}

//NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
BOOLEAN ComInitWin10Commmunication() {
	ULONG kernelSize = 0;
	ULONG64 base = (ULONG64)KrGetKernelModuleBase("ntoskrnl.exe", &kernelSize);
	ULONG size = 0;
	ULONG ret = PeGetSectionOffsetByName(base, "PAGE", &size);
	PUCHAR func = MmFindAddrBySignCode((PUCHAR)ret + base,
		"65488B04258801000080B8??????????0F84????????F6C2037405E8????????488D42??48B90000FFFFFF7F0000483BC17705483BC2730B33C0A20000FFFFFF7F00004C8B32"
		, size);
	func = MmFindAddrBySignCode(func, "75??488B05????????E8????????8BC885C07840", 0x200);
	PULONG64 global = (PULONG64)(*(PLONG)(func + 5) + func + 5 + 4);
	oldCallBack_Win10_off_140401C70 = (Win10_off_140401C70CallBack)global[0];
	global[0] = CallBack_Win10_off_140401C70;
	return TRUE;
}
VOID ComUnloadWin10Communication() {
	ULONG kernelSize = 0;
	ULONG64 base = (ULONG64)KrGetKernelModuleBase("ntoskrnl.exe", &kernelSize);
	ULONG size = 0;
	ULONG ret = PeGetSectionOffsetByName(base, "PAGE", &size);
	PUCHAR func = MmFindAddrBySignCode((PUCHAR)ret + base,
		"65488B04258801000080B8??????????0F84????????F6C2037405E8????????488D42??48B90000FFFFFF7F0000483BC17705483BC2730B33C0A20000FFFFFF7F00004C8B32"
		, size);
	func = MmFindAddrBySignCode(func, "75??488B05????????E8????????8BC885C07840", 0x200);
	PULONG64 global = (PULONG64)(*(PLONG)(func + 5) + func + 5 + 4);
	global[0] = oldCallBack_Win10_off_140401C70;
}

BOOLEAN ComInitWin11Commmunication() {
	ULONG kernelSize = 0;
	ULONG64 base = (ULONG64)KrGetKernelModuleBase("ntoskrnl.exe", &kernelSize);
	ULONG size = 0;
	ULONG ret = PeGetSectionOffsetByName(base, "PAGE", &size);
	PUCHAR func = MmFindAddrBySignCode((PUCHAR)ret + base,
		"488BC4488958??488970??488978??41564883EC??498BD9498BF8408AF1488360????488360????65488B04258801000080B8??????????0F84????????F6C2??74??E8????????488D42??48B90000FFFFFF7F0000483BC177??483BC273??"
		, size);
	func = MmFindAddrBySignCode(func, "75??488B05????????E8????????8BC885C07840", 0x200);
	PULONG64 global = (PULONG64)(*(PLONG)(func + 5) + func + 5 + 4);
	oldCallBack_Win10_off_140401C70 = (Win10_off_140401C70CallBack)global[0];
	global[0] = CallBack_Win10_off_140401C70;
	return TRUE;
}
VOID ComUnloadWin11Communication() {
	ULONG kernelSize = 0;
	ULONG64 base = (ULONG64)KrGetKernelModuleBase("ntoskrnl.exe", &kernelSize);
	ULONG size = 0;
	ULONG ret = PeGetSectionOffsetByName(base, "PAGE", &size);
	PUCHAR func = MmFindAddrBySignCode((PUCHAR)ret + base,
		"488BC4488958??488970??488978??41564883EC??498BD9498BF8408AF1488360????488360????65488B04258801000080B8??????????0F84????????F6C2??74??E8????????488D42??48B90000FFFFFF7F0000483BC177??483BC273??"
		, size);
	func = MmFindAddrBySignCode(func, "75??488B05????????E8????????8BC885C07840", 0x200);
	PULONG64 global = (PULONG64)(*(PLONG)(func + 5) + func + 5 + 4);
	global[0] = oldCallBack_Win10_off_140401C70;
}



BOOLEAN ComInitCommmunication() {
	
	VER_INFO.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion(&VER_INFO);

	if (VER_INFO.dwBuildNumber == 7601 || VER_INFO.dwBuildNumber == 7600)
	{
		return ComInitWin7Commmunication();
	}
	else if (VER_INFO.dwBuildNumber == 22000) {
		return ComInitWin11Commmunication();
	}
	else
	{
		return ComInitWin10Commmunication();
	}
}

VOID ComUnloadCommmunication() {
	//RTL_OSVERSIONINFOEXW info = { 0 };
	//info.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	//RtlGetVersion(&info);

	if (VER_INFO.dwBuildNumber == 7601 || VER_INFO.dwBuildNumber == 7600)
	{
		ComUnloadWin7Communication();
	}
	else if (VER_INFO.dwBuildNumber == 22000) {
		ComUnloadWin11Communication();
	}
	else
	{
		ComUnloadWin10Communication();
	}
}

NTSTATUS ComHandlePackage(PComPackage pack) {
	//DbgBreakPoint();
	switch (pack->cmd)
	{
	case CMD_TEST:
	{
		//DbgPrintEx(77,0,"[Silky Log]:测试通信包成功接收！\r\n");
		pack->status = STATUS_SUCCESS;
		break;
	}
	case CMD_GET_MODULE_BASE:
	{
		if (!MmIsAddressValid(pack->outData))
		{
			pack->status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG_PTR base = KrGetProcModuleBaseByName(pack->inLen,(PUCHAR)pack->inData);
		*(PULONG64)(pack->outData) = (ULONG64)base;
		//DbgPrintEx(77, 0, "[Silky Log]:取【%d】进程的模块【%s】的基址，值为【0x%10X】！\r\n", pack->inLen, (PUCHAR)pack->inData, base);
		if (!base)
		{
			pack->status = STATUS_UNSUCCESSFUL;
		}
		else
		{
			pack->status = STATUS_SUCCESS;
		}
		break;
	}
	case CMD_READ_MDL:
	{
		if (MmReadProcessMemory_MDL(pack->outLen, pack->inData, pack->outData, pack->inLen)){
			pack->status = STATUS_SUCCESS;
		}else{
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_READ_MDL_WITH_TRY:
	{
		if (MmReadProcessMemory_MDLWithTry(pack->outLen, pack->inData, pack->outData, pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_READ_APICOPY:
	{
		if (MmReadProcessMemory_ApiCopy(pack->outLen, pack->inData, pack->outData, pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		//PUCHAR t = (PUCHAR)ExAllocatePool(NonPagedPool, pack->inLen+0x100);
		//for (ULONG64 i = 0; i < pack->inLen; i++)
		//{
		//	sprintf(t, "%02X ", *(PUCHAR)(pack->outData + i));
		//}
		//DbgPrintEx(77, 0, "[Silky Log]:读【%d】进程的【0x%10X】地址，长度为【0x%10X】字节，读出值为【%s】！\r\n", pack->outLen, pack->inData, pack->inLen, t);
		//ExFreePool(t);
		break;
	}
	case CMD_READ_ATTACH:
	{
		if (MmReadProcessMemory_Attach(pack->outLen, pack->inData, pack->outData, pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		//PUCHAR t = (PUCHAR)ExAllocatePool(NonPagedPool, pack->inLen + 0x100);
		//for (ULONG64 i = 0; i < pack->inLen; i++)
		//{
		//	sprintf(t, "%02X ", *(PUCHAR)(pack->outData + i));
		//}
		//DbgPrintEx(77, 0, "[Silky Log]:读【%d】进程的【0x%10X】地址，长度为【0x%10X】字节，读出值为【%s】！\r\n", pack->outLen, pack->inData, pack->inLen, t);
		//ExFreePool(t);
		break;
	}
	case CMD_WRITE:
	{
		if (MmWriteProcessMemory(pack->outLen, pack->inData, pack->outData, pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		//PUCHAR t = (PUCHAR)ExAllocatePool(NonPagedPool, pack->inLen + 0x100);
		//for (ULONG64 i = 0; i < pack->inLen; i++)
		//{
		//	sprintf(t, "%02X ", *(PUCHAR)(pack->outData + i));
		//}
		//DbgPrintEx(77, 0, "[Silky Log]:写【%d】进程的【0x%16X】地址，长度为【0x%16X】字节，写的值为【%s】！\r\n", pack->outLen, pack->inData, pack->inLen, t);
		//ExFreePool(t);
		break;
	}
	case CMD_INIT_PROC_PROTECT:
	{
		if (KrInitProtectProcessByObjCallbackWithPatchAndJmpEcx()) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_ADD_PROC_PROTECT:
	{
		KrAddProtectProcessByObjCallbackWithPatchAndJmpEcx(pack->inLen);
		pack->status = STATUS_SUCCESS;
		break;
	}
	case CMD_UNLOAD_PROC_PROTECT:
	{
		KrUnloadProtectProcessByObjCallbackWithPatchAndJmpEcx();
		pack->status = STATUS_SUCCESS;
		break;
	}
	case CMD_REMOTE_CALL:
	{
		if (MmRemoteCallByWriteContext(pack->inData)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_GET_PROC_ADDR:
	{
		if (!MmIsAddressValid(pack->outLen))
		{
			pack->status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG64 funcAddr = PeGetExportFuncAddrOfProcModule(pack->inLen,(char*)pack->inData, (char*)pack->outData);
		if (funcAddr) {
			*(PULONG64)(pack->outLen) = funcAddr;
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_ALLOC_MEM:
	{
		ULONG64 base = MmAllocateProcMemory(pack->inData, pack->inLen);
		*(PULONG64)(pack->outData) = base;
		if (base) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_FREE_MEM:
	{
		if (MmFreeProcMemory(pack->inData,pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_FIND_SIGN:
	{
		PFindSignPackage sign = (PFindSignPackage)pack->inData;
		ULONG64 base = MmFindProcAddrBySignCode(sign->pid,sign->base,sign->code,sign->len);
		*(PULONG64)(pack->outData) = base;
		if (base) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_HIDE_PROC:
	{
		if (FcProtectProcessByGlobalHandleTable(pack->inData,pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_UNLOAD_DRIVER:
	{
		ComUnloadCommmunication();
		pack->status = STATUS_SUCCESS;
		break;
	}
	case CMD_BYPASS_VIRTUAL:
	{
		if (PsVirtualByPass(pack->inData)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_DEL_FILE:
	{
		if (FsDeleteFile(pack->inData)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}




	case CMD_KM_INSTALL:
	{
		if (KmInstall()) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_KM_KEY:
	{
		if (KmKeyDownUp((PKEYBOARD_INPUT_DATA)pack->inData)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_KM_MOUSE:
	{
		if (KmMouseDownUp((PKEYBOARD_INPUT_DATA)pack->inData)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case CMD_READ_VIRBYPASS:
	{
		if (MmReadProcessMemory_VirBypass(pack->outLen, pack->inData, pack->outData, pack->inLen)) {
			pack->status = STATUS_SUCCESS;
		}
		else {
			pack->status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	//case CMD_WRITE_VIRBYPASS:
	//{
	//	if (MmWriteProcessMemory_VirBypass(pack->outLen, pack->inData, pack->outData, pack->inLen)) {
	//		pack->status = STATUS_SUCCESS;
	//	}
	//	else {
	//		pack->status = STATUS_UNSUCCESSFUL;
	//	}
	//	break;
	//}
	default:
		break;
	}
	return pack->status;
}


BOOLEAN MmReadProcessMemory_Attach(ULONG64 pid,ULONG64 dst,PUCHAR buf,ULONG64 len) {
	if (dst>=MmHighestUserAddress || (dst+len)>MmHighestUserAddress)
	{
		return FALSE;
	}
	PEPROCESS proc = NULL;
	NTSTATUS ret = NULL;
	ULONG64 oldEproc = NULL;
	BOOLEAN noneedDeference = TRUE;
	proc = GetBypassEprocess(pid);
	if (!proc)
	{
		noneedDeference = FALSE;
		ret = PsLookupProcessByProcessId(pid, &proc);
		if (!NT_SUCCESS(ret))
		{
			return FALSE;
		}
	}
	PUCHAR mm = (PUCHAR)ExAllocatePool(NonPagedPool,len);
	if (!mm)
	{
		if (!noneedDeference)
		{
			ObDereferenceObject(proc);
		}
		return FALSE;
	}
	PKTHREAD currentThread = KeGetCurrentThread();
	oldEproc = (ULONG64)IoGetCurrentProcess();
	ULONG64 eprocOffset = KrGetEprocessOffset();
	*(PULONG64)((ULONG64)currentThread + eprocOffset) = proc;
	memset(mm, 0, len);
	KAPC apc = { 0 };
	KeStackAttachProcess(proc,&apc);
	if (MmIsAddressValid(dst) && MmIsAddressValid(dst+len))
	{
		memcpy(mm,(PUCHAR)dst,len);
	}
	KeUnstackDetachProcess(&apc);
	memcpy((PUCHAR)buf,mm,len);
	ExFreePool(mm);
	if (!noneedDeference)
	{
		ObDereferenceObject(proc);
	}
	*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
	return TRUE;
}

PUCHAR MmMapMdl(PMDL* mdl,ULONG64 dst,ULONG64 len,PMDL_RET ret) {
	*mdl = IoAllocateMdl(dst, len, FALSE, FALSE, NULL);
	PUCHAR addr = NULL;
	if (!*mdl)
	{
		return NULL;
	}
	ret->rIoAllocateMdl = TRUE;
	__try {
		MmProbeAndLockPages(*mdl, UserMode, IoReadAccess);
		ret->rMmProbeAndLockPages = TRUE;
		addr = MmMapLockedPagesSpecifyCache(*mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
		ret->rMmMapLockedPagesSpecifyCache = TRUE;
	}__except(1){
		return NULL;
	}
	return addr;
}

VOID MmUnMapMdl(PMDL* mdl,PMDL_RET ret,PVOID base) {
	if (ret->rMmMapLockedPagesSpecifyCache)
	{
		MmUnmapLockedPages(base, *mdl);
	}
	if (ret->rMmProbeAndLockPages)
	{
		MmUnlockPages(*mdl);
	}
	if (ret->rIoAllocateMdl)
	{
		IoFreeMdl(*mdl);
	}
}

BOOLEAN MmReadProcessMemory_MDL(ULONG64 pid, ULONG64 dst, PUCHAR buf, ULONG64 len) {
	if (dst >= MmHighestUserAddress || (dst + len) > MmHighestUserAddress)
	{
		return FALSE;
	}
	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return FALSE;
	}
	PUCHAR mm = (PUCHAR)ExAllocatePool(NonPagedPool, len);
	if (!mm)
	{
		ObDereferenceObject(proc);
		return FALSE;
	}
	memset(mm, 0, len);
	KAPC apc = { 0 };
	KeStackAttachProcess(proc, &apc);
	//====================================
	MDL_RET mdlRet = { 0 };
	PMDL mdl = NULL;
	PUCHAR addr = MmMapMdl(&mdl,dst,len,&mdlRet);
	if (MmIsAddressValid(addr) && MmIsAddressValid(addr + len))
	{
		memcpy(mm, (PUCHAR)addr, len);
	}
	MmUnMapMdl(&mdl,&mdlRet,addr);
	//===============================================
	KeUnstackDetachProcess(&apc);
	memcpy((PUCHAR)buf, mm, len);
	ExFreePool(mm);
	ObDereferenceObject(proc);
	return TRUE;
}

BOOLEAN MmReadProcessMemory_MDLWithTry(ULONG64 pid, ULONG64 dst, PUCHAR buf, ULONG64 len) {
	//ExLockUserBuffer + ExUnlockUserBuffer  防止内存加载驱动时无Try蓝屏  wdk有参数说明
	return TRUE;
}

ULONG64 KrGetEprocessOffset() {
	ULONG64 offset = 0;
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		offset = 0x210;
	}
	else
	{
		offset = 0x220;
	}
	return offset;
}

BOOLEAN MmReadProcessMemory_ApiCopy(ULONG64 pid, ULONG64 dst, PUCHAR buf, ULONG64 len) {
	if (dst >= MmHighestUserAddress || (dst + len) > MmHighestUserAddress)
	{
		return FALSE;
	}
	PEPROCESS proc = NULL;
	ULONG64 oldEproc = NULL;
	NTSTATUS ret = NULL;
	BOOLEAN noneedDeference = TRUE;
	proc = GetBypassEprocess(pid);
	if (!proc)
	{
		noneedDeference = FALSE;
		ret = PsLookupProcessByProcessId(pid, &proc);
		if (!NT_SUCCESS(ret))
		{
			return FALSE;
		}
	}
	PKTHREAD currentThread = KeGetCurrentThread();
	oldEproc = (ULONG64)IoGetCurrentProcess();
	ULONG64 eprocOffset = KrGetEprocessOffset();
	*(PULONG64)((ULONG64)currentThread + eprocOffset) = proc;
	
	SIZE_T retSize = 0;
	ret = MmCopyVirtualMemory(proc,dst,IoGetCurrentProcess(), buf, len,UserMode, &retSize);
	if (!noneedDeference)
	{
		ObDereferenceObject(proc);
	}
	*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
	return NT_SUCCESS(ret);
}

ULONG64 KrGetVirtualProtectFuncAddr() {
	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName,L"ZwIsProcessInJob");
	PUCHAR funcAddr = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
	return MmFindAddrBySignCode(funcAddr+0x10,"488BC4FA",0x200);
}

BOOLEAN MmWriteProcessMemory(ULONG64 pid, ULONG64 dst, PUCHAR buf, ULONG64 len) {
	if (dst >= MmHighestUserAddress || (dst + len) > MmHighestUserAddress)
	{
		return FALSE;
	}
	PEPROCESS dstProc = GetBypassEprocess(pid);
	NTSTATUS ret = NULL;
	ULONG64 oldEproc = NULL;
	BOOLEAN noneedDeference = TRUE;
	if (!dstProc)
	{
		noneedDeference = FALSE;
		ret = PsLookupProcessByProcessId(pid, &dstProc);
		if (!NT_SUCCESS(ret))
		{
			return FALSE;
		}
	}
	PKTHREAD currentThread = KeGetCurrentThread();
	oldEproc = (ULONG64)IoGetCurrentProcess();
	ULONG64 eprocOffset = KrGetEprocessOffset();
	*(PULONG64)((ULONG64)currentThread + eprocOffset) = dstProc;
	PEPROCESS currentProc = IoGetCurrentProcess();
	//直接写入
	SIZE_T retSize = 0;
	ret = MmCopyVirtualMemory(currentProc, buf, dstProc, dst,  len, UserMode, &retSize);
	if (NT_SUCCESS(ret))
	{
		if (!noneedDeference)
		{
			ObDereferenceObject(dstProc);
		}
		*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
		return TRUE;
	}
	//修改内存属性
	ULONG64 tmp = dst;
	ULONG64 tmpLen = len;
	ULONG64 oldProtect = NULL;
	pZwProtectVirtualMemory ProtectVirtualMemory = (pZwProtectVirtualMemory)KrGetVirtualProtectFuncAddr();
	if (!ProtectVirtualMemory)
	{
		if (!noneedDeference)
		{
			ObDereferenceObject(dstProc);
		}
		*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
		return FALSE;
	}
	KAPC apc = { 0 };
	KeStackAttachProcess(dstProc,&apc);
	ret = ProtectVirtualMemory(-1,&tmp, &tmpLen, PAGE_EXECUTE_READWRITE,&oldProtect);
	if (!NT_SUCCESS(ret))
	{
		KeUnstackDetachProcess(&apc);
		if (!noneedDeference)
		{
			ObDereferenceObject(dstProc);
		}
		*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
		return FALSE;
	}
	//再次写入
	ret = MmCopyVirtualMemory(currentProc, buf, dstProc, dst, len, UserMode, &retSize);
	ProtectVirtualMemory(-1, &tmp, &tmpLen, oldProtect, &oldProtect);
	if (NT_SUCCESS(ret))
	{
		KeUnstackDetachProcess(&apc);
		if (!noneedDeference)
		{
			ObDereferenceObject(dstProc);
		}
		*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
		return TRUE;
	}

	//修改CR0写入
	_disable();
	ULONG64 oldCr0 = __readcr0();
	__writecr0(oldCr0 & ~(0x10000));
	ret = MmCopyVirtualMemory(currentProc, buf, dstProc, dst, len, UserMode, &retSize);
	__writecr0(oldCr0);
	_enable();
	KeUnstackDetachProcess(&apc);
	if (!noneedDeference)
	{
		ObDereferenceObject(dstProc);
	}
	*(PULONG64)((ULONG64)currentThread + eprocOffset) = oldEproc;
	return NT_SUCCESS(ret);
}

BOOLEAN MmWriteKernelMemory(ULONG64 dst,PUCHAR buf,ULONG64 len) {
	if (!MmIsAddressValid((PVOID)dst)|| !MmIsAddressValid((PVOID)(dst+len)))
	{
		return FALSE;
	}
	PPHYSICAL_ADDRESS pAddr = NULL;
	PUCHAR newAddr = MmMapIoSpace(MmGetPhysicalAddress(dst),len,MmNonCached);
	if (!MmIsAddressValid((PVOID)newAddr) || !MmIsAddressValid((PVOID)(newAddr + len)))
	{
		return FALSE;
	}
	memcpy(newAddr,buf,len);
	return TRUE;
}

extern POBJECT_TYPE * IoDriverObjectType;
PVOID RegisterHandle = NULL;
ULONG64 pidList[0x100] = { 0 };
ULONG64 indexPidList = 0;
BOOLEAN alreadyInitObjCallback = FALSE;

OB_PREOP_CALLBACK_STATUS preCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	PEPROCESS proc = OperationInformation->Object;
	if (!proc)
	{
		return OB_PREOP_SUCCESS;
	}

	ULONG64 currentPid = PsGetCurrentProcessId();
	ULONG64 dstPid = PsGetProcessId(proc);
	if (!dstPid || !currentPid)
	{
		return OB_PREOP_SUCCESS;
	}
	for (ULONG64 i = 0; i < indexPidList; i++)
	{
		if (pidList[i] == currentPid)
		{
			return OB_PREOP_SUCCESS;
		}

		if (pidList[i] == dstPid)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
			}
			else
			{
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
				OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
			}
			return OB_PREOP_SUCCESS;
		}
	}
	return OB_PREOP_SUCCESS;
}

NTSTATUS ObRegObjCallbackToNtoskrnlWithPatch(PULONG64 callBack){
	//   \\Driver\\WMIxWDM
	UNICODE_STRING ntName = { 0 };
	RtlInitUnicodeString(&ntName,L"\\Driver\\WMIxWDM");
	PDRIVER_OBJECT  driverObject = NULL;
	NTSTATUS status = ObReferenceObjectByName(&ntName, FILE_ALL_ACCESS, 0, 0, *IoDriverObjectType, KernelMode, NULL,&driverObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ULONG64 size = 0;
	ULONG64 textOffset = PeGetSectionOffsetByName(driverObject->DriverStart,".text",&size);
	if (!textOffset)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PUCHAR jmpEcx = MmFindAddrBySignCode((PUCHAR)(driverObject->DriverStart)+ textOffset,"FFE1", size);

	struct _LDR_DATA_TABLE_ENTRY* entry = (struct _LDR_DATA_TABLE_ENTRY*)driverObject->DriverSection;
	OB_OPERATION_REGISTRATION opinfo = { 0 };
	opinfo.ObjectType = PsProcessType;
	opinfo.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opinfo.PreOperation = jmpEcx;
	opinfo.PostOperation = NULL;
	OB_CALLBACK_REGISTRATION obCallback = { 0 };

	obCallback.Version = OB_FLT_REGISTRATION_VERSION;
	obCallback.OperationRegistrationCount = 1;
	RtlInitUnicodeString(&obCallback.Altitude, L"624440");
	obCallback.OperationRegistration = &opinfo;
	obCallback.RegistrationContext = preCallback;

	BOOLEAN patch = KrPatchObRegisterCallbacks();
	if (!patch)
	{
		ObDereferenceObject(driverObject);
		return STATUS_UNSUCCESSFUL;
	}
	status = ObRegisterCallbacks(&obCallback, &RegisterHandle);
	KrUnPatchObRegisterCallbacks();
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(driverObject);
		return status;
	}
	ObDereferenceObject(driverObject);
	return status;
}

PUCHAR MmGetMmVerifyCallbackFunctionCheckFlagsAddr() {
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name, L"ObRegisterCallbacks");
	PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&name);
	if (!func)
	{
		return NULL;
	}
	//RTL_OSVERSIONINFOEXW version = { 0 };
	//NTSTATUS status = RtlGetVersion(&version);
	//if (!NT_SUCCESS(status))
	//{
	//	return NULL;
	//}
	PUCHAR pMmVerifyCallbackFunction = NULL;
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		PUCHAR ret = MmFindAddrBySignCode(func, "74??E8????????3BC374??488B4C2E??483BCB74??E8????????3BC374", 0x1000);
		if (!ret)
		{
			return NULL;
		}
		pMmVerifyCallbackFunction = *(PLONG)(ret + 3) + ret + 7;
	}
	else
	{
		PUCHAR ret = MmFindAddrBySignCode(func, "BA????????E8????????85C00F84????????498B4E??4885C90F85????????48C1E3??4883C3??4803DE488D4B", 0x1000);
		if (!ret)
		{
			return NULL;
		}
		pMmVerifyCallbackFunction = *(PLONG)(ret + 6) + ret + 10;
	}
	return pMmVerifyCallbackFunction;
}

ULONG64 oldMmVerifyCallbackFunction = 0;
BOOLEAN KrPatchObRegisterCallbacks() {
	PUCHAR pMmVerifyCallbackFunction = MmGetMmVerifyCallbackFunctionCheckFlagsAddr();
	if (!pMmVerifyCallbackFunction)
	{
		return FALSE;
	}
	//B0 01 C3
	ULONG64 newCode = 0x90C301B0;
	oldMmVerifyCallbackFunction = *(PULONG64)(pMmVerifyCallbackFunction);
	//mov eax,[pMmVerifyCallbackFunction]
	//mov edx,0x90C301B0
	//cmpxchg dword ptr ds:[pMmVerifyCallbackFunction],edx
	/*这条指令将al\ax\eax\rax中的值与首操作数比较:

1.如果相等，第2操作数的直装载到首操作数，zf置1。(相当于相减为0，所以0标志位置位)

2.如果不等， 首操作数的值装载到al\ax\eax\rax，并将zf清0*/
	return MmWriteKernelMemory((ULONG64)pMmVerifyCallbackFunction,&newCode,4);
}

VOID KrUnPatchObRegisterCallbacks() {
	if (!oldMmVerifyCallbackFunction)
	{
		return;
	}
	PUCHAR pMmVerifyCallbackFunction = MmGetMmVerifyCallbackFunctionCheckFlagsAddr();
	if (!pMmVerifyCallbackFunction)
	{
		return;
	}
	MmWriteKernelMemory((ULONG64)pMmVerifyCallbackFunction, &oldMmVerifyCallbackFunction, 4);
}

PUCHAR KrGetPsSuspendThreadAddr() {
	ULONG size = 0;
	PUCHAR base = KrGetKernelModuleBase("ntoskrnl.exe", &size);
	if (!base)
	{
		return NULL;
	}
	ULONG offset = PeGetSectionOffsetByName(base, "PAGE", &size);
	if (!offset)
	{
		return NULL;
	}

	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		PUCHAR addr = MmFindAddrBySignCode(base+offset,
			"4C8BEA488BF133FF897C24??654C8B2425880100004C89A424????????6641FF8C24????????4881C1????????0F0D09488B014883E0FE488D5002F0480FB1110F85????????8B86????????A8010F85????????488BCEE8????????894424??897C24??EB??894424??8944??2033FF4C8B6C24??488B7424??4C8BA424????????8B86????????A8010F85????????488D8E????????0F0D09488B014883E0FE488D50FEF0480FB1110F85"
			, size);
		if (!addr)
		{
			return NULL;
		}
		return addr-21;
	}
	else {
		PUCHAR addr = MmFindAddrBySignCode(base + offset,
			"4C8BF2488BF9836424????65488B34258801000048897424??66FF8E????????4C8DB9????????4C897C24??498BCFE8????????84C00F84????????8B87????????A8010F85????????488BCFE8????????894424??33DB895C24??EB??8BD8894424??4C8B7424??488B7C24??488B7424??4C8B7C24??498BCFE8????????4D85F674??8B4424??41890685C075??488B97????????F782????????????????0F85"
			, size);
		if (!addr)
		{
			return NULL;
		}
		return addr - 21;
	}
}
PUCHAR KrGetPsResumeThreadAddr() {
	ULONG size = 0;
	PUCHAR base = KrGetKernelModuleBase("ntoskrnl.exe", &size);
	if (!base)
	{
		return NULL;
	}
	ULONG offset = PeGetSectionOffsetByName(base, "PAGE", &size);
	if (!offset)
	{
		return NULL;
	}

	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		PUCHAR addr = MmFindAddrBySignCode(base + offset,
			"FFF34883EC??488BDAE8????????4885DB7402890333C04883C4??5BC3"
			, size);
		return addr;
	}
	else if (VER_INFO.dwBuildNumber == 22000)
	{
		UNICODE_STRING name = { 0 };
		RtlInitUnicodeString(&name, L"PsSuspendProcess");
		PUCHAR pPsSuspendProcess = MmGetSystemRoutineAddress(&name);
		return MmFindAddrBySignCode(pPsSuspendProcess-0x100,"4883EC??41B801000000E8????????4883C4??C3",0x100);
	} 
	else
	{
		PUCHAR addr = MmFindAddrBySignCode(base + offset,
			"48895C24??48897424??574883EC??488BDA488BF9E8????????65488B1425????????8BF083F80175??4C8B87????????B800800000418B88????????85C874??0FBAE1??0F82????????4885DB74??8933488B5C24??33C0488B7424??4883C4??5FC3"
			, size);
		return addr;
	}
}


/*
	pidList[indexRegisterHandle] = pid;
	indexRegisterHandle++;*/
BOOLEAN KrInitProtectProcessByObjCallbackWithPatchAndJmpEcx() {
	NTSTATUS status = ObRegObjCallbackToNtoskrnlWithPatch((PULONG64)preCallback);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	alreadyInitObjCallback = TRUE;
	return TRUE;
}

VOID KrAddProtectProcessByObjCallbackWithPatchAndJmpEcx(ULONG64 pid) {
	pidList[indexPidList] = pid;
	indexPidList++;
}

VOID KrUnloadProtectProcessByObjCallbackWithPatchAndJmpEcx() {
	if (alreadyInitObjCallback)
	{
		for (ULONG64 i = 0; i < 0x100; i++)
		{
			pidList[i] = 0;
		}
		indexPidList = 0;
		ObUnRegisterCallbacks(RegisterHandle);
	}
}

BOOLEAN MmRemoteCallByWriteContext(PRemoteCallPackage pack) {
	PEPROCESS proc = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pack->pid,&proc);
	BOOLEAN ret = FALSE;
	if (!NT_SUCCESS(status))
	{
		goto OB_RET;
	}
	PETHREAD thread = NULL;
	status = PsLookupThreadByThreadId(pack->tid, &thread);
	if (!NT_SUCCESS(status))
	{
		goto OB_PROC;
	}
	PEPROCESS apcProc = PsGetThreadApcProcess(thread);
	if (!apcProc || apcProc != proc)
	{
		goto OB_ALL;
	}
	PsSuspendThreadProc SuspendThread = (PsSuspendThreadProc)KrGetPsSuspendThreadAddr();
	PsResumeThreadProc ResumeThread = (PsResumeThreadProc)KrGetPsResumeThreadAddr();
	if (!SuspendThread || !ResumeThread)
	{
		goto OB_ALL;
	}

	PPEB32 peb32 = PsGetWow64ProcPeb32(proc);
	
	status = SuspendThread(thread, NULL);
	if (!NT_SUCCESS(status))
	{
		goto OB_ALL;
	}
	if (peb32)
	{
		ret = MmRemoteCallToWow64Proc(pack, thread, proc);
	}
	else {
		//X64
		ret = MmRemoteCallToX64Proc(pack, thread, proc);
	}
	status = ResumeThread(thread, NULL);
	ret = NT_SUCCESS(status);
OB_ALL:
	ObDereferenceObject(thread);
OB_PROC:
	ObDereferenceObject(proc);
OB_RET:
	return ret;
}


VOID RMC_FreeVirtualMemory(PRemoteCallPackage pack) {
	PEPROCESS proc = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(pack->pid, &proc);
	BOOLEAN ret = FALSE;
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pack);
		return;
	}
	PETHREAD thread = NULL;
	status = PsLookupThreadByThreadId(pack->tid, &thread);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pack);
		ObDereferenceObject(proc);
		return;
	}

	KAPC_STATE apc = { 0 };
	PULONG sign = (PULONG)ExAllocatePool(NonPagedPool,8);
	KeStackAttachProcess(proc,&apc);
	while (1)
	{
		if (PsGetProcessExitStatus(proc) != 0x103)
		{
			break;
		}
		memcpy(sign, pack->shellcode + pack->signOffset,4);
		if (*sign) 
		{
			break;
		}
		CpMySleepMin(100);
	}
	ULONG64 len = pack->codeLen + 0x500;
	ZwFreeVirtualMemory(-1, &pack->shellcode, &len, MEM_RELEASE);
	KeUnstackDetachProcess(&apc);
	ExFreePool(pack);
	ObDereferenceObject(proc);
	ObDereferenceObject(thread);
}

BOOLEAN MmRemoteCallToX64Proc(PRemoteCallPackage pack, PETHREAD thread, PEPROCESS proc) {
	if (pack->mode!= RCM_X64)
	{
		return FALSE;
	}
	PKTRAP_FRAME trapFrame = PsGetThreadTrapFrame(thread);
	if (!trapFrame)
	{
		return FALSE;
	}
	PUCHAR codeT = (PUCHAR)ExAllocatePool(NonPagedPool,pack->codeLen+0x500);
	if (!codeT)
	{
		return FALSE;
	}
	PRemoteCallPackage packT = (PRemoteCallPackage)ExAllocatePool(NonPagedPool, sizeof(RemoteCallPackage));
	if (!packT)
	{
		ExFreePool(codeT);
		return FALSE;
	}
	memset(packT, 0, sizeof(RemoteCallPackage));
	memcpy(packT, pack, sizeof(RemoteCallPackage));
	UCHAR assm[] = { 0x50,0x48,0xB8,0x78,0x56,0x34,0x12,0x78,0x56,0x34,0x12,0x48,0xFF,0x00,0x58,0xFF,0x25,0x00,0x00,0x00,0x00 };
	/*
	push rax
	mov rax,XXX
	inc qword ptr ds:[rax]
	pop rax
	jmp [xxxx]
	*/
	memset(codeT, 0, packT->codeLen + 0x500);
	memcpy(codeT, packT->shellcode, packT->codeLen);
	memcpy(codeT + packT->codeLen, assm, sizeof(assm));

	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(proc,&apc);

	PUCHAR base = NULL;
	ULONG64 size = packT->codeLen + 0x500;
	NTSTATUS status = ZwAllocateVirtualMemory(-1,&base,NULL,&size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(codeT);
		ExFreePool(packT);
		KeUnstackDetachProcess(&apc);
		return FALSE;
	}
	memcpy(base, codeT, packT->codeLen + 0x500);
	ULONG64 sign = (ULONG64)base + packT->codeLen + sizeof(assm);
	*(PULONG64)(base + packT->codeLen + 0x3) = sign+8;
	*(PULONG64)(sign) = trapFrame->Rip;
	trapFrame->Rip = base;
	ExFreePool(codeT);
	KeUnstackDetachProcess(&apc);

	HANDLE tHandle = NULL;
	packT->shellcode = base;
	packT->signOffset = packT->codeLen + sizeof(assm) + 8;
	status = PsCreateSystemThread(&tHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, RMC_FreeVirtualMemory, packT);
	if (NT_SUCCESS(status)) {
		ZwClose(tHandle);//相当于CloseHandle
	}

	return TRUE;
}

BOOLEAN MmRemoteCallToWow64Proc(PRemoteCallPackage pack, PETHREAD thread, PEPROCESS proc) {
	if (pack->mode != RCM_WOW64)
	{
		return FALSE;
	}
	PTEB64 teb = PsGetThreadTeb64(thread);
	if (!teb)
	{
		return FALSE;
	}
	UCHAR assm[] = { 0xFF,0x05,0,0,0,0,0xFF,0x25,0,0,0,0 };

	PUCHAR codeT = (PUCHAR)ExAllocatePool(NonPagedPool, pack->codeLen + 0x500);
	if (!codeT)
	{
		return FALSE;
	}
	PRemoteCallPackage packT = (PRemoteCallPackage)ExAllocatePool(NonPagedPool, sizeof(RemoteCallPackage));
	if (!packT)
	{
		ExFreePool(codeT);
		return FALSE;
	}
	memset(packT, 0, sizeof(RemoteCallPackage));
	memcpy(packT, pack, sizeof(RemoteCallPackage));
	memset(codeT, 0, packT->codeLen + 0x500);
	memcpy(codeT, packT->shellcode, packT->codeLen);
	memcpy(codeT + packT->codeLen, assm, sizeof(assm));

	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(proc, &apc);
	PCONTEXT32 con = (PCONTEXT32)((PUCHAR)teb->TlsSlots[1] + 4);

	PUCHAR base = NULL;
	ULONG64 size = packT->codeLen + 0x500;
	NTSTATUS status = ZwAllocateVirtualMemory(-1, &base, NULL, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(codeT);
		ExFreePool(packT);
		KeUnstackDetachProcess(&apc);
		return FALSE;
	}
	memcpy(base, codeT, packT->codeLen + 0x500);

	ULONG64 sign = (ULONG64)base + packT->codeLen + sizeof(assm);

	*(PULONG)(base + packT->codeLen + 0x2) = sign + 8;
	*(PULONG)(base + packT->codeLen + 0x8) = sign;
	*(PULONG64)(sign) = con->Eip;
	con->Eip = base;
	ExFreePool(codeT);
	KeUnstackDetachProcess(&apc);

	HANDLE tHandle = NULL;
	packT->shellcode = base;
	packT->signOffset = packT->codeLen + sizeof(assm) + 8;
	status = PsCreateSystemThread(&tHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, RMC_FreeVirtualMemory, packT);
	if (NT_SUCCESS(status)) {
		ZwClose(tHandle);//相当于CloseHandle
	}
	return TRUE;
}

ULONG64 PeGetExportFuncAddrOfProcModule(ULONG64 pid, char* moduleName,char* funcName) {
	if (pid == NULL)
	{
		return NULL;
	}
	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return NULL;
	}
	PUCHAR mName = (PUCHAR)ExAllocatePool(NonPagedPool,strlen(moduleName)+100);
	if (!mName)
	{
		ObDereferenceObject(proc);
		return NULL;
	}
	memset(mName, 0, strlen(moduleName) + 100);


	PUCHAR fName = (PUCHAR)ExAllocatePool(NonPagedPool, strlen(funcName) + 100);
	if (!fName)
	{
		ObDereferenceObject(proc);
		return NULL;
	}
	memset(fName, 0, strlen(funcName) + 100);

	ULONG64 addr = 0;
	KAPC_STATE apc = { 0 };
	while (MmIsAddressValid(funcName) && MmIsAddressValid(moduleName) && MmIsAddressValid(funcName+ strlen(funcName)) && MmIsAddressValid(moduleName)+ strlen(moduleName))
	{
		memcpy(fName, funcName, strlen(funcName) + 1);
		memcpy(mName, moduleName, strlen(moduleName) + 1);
		KeStackAttachProcess(proc, &apc);
		ULONG64 base = (ULONG64)KrGetProcModuleBaseByName(pid, mName);
		if (!base)
		{
			KeUnstackDetachProcess(&apc);
			break;
		}
		addr = (ULONG64)PeGetExportFuncAddr64((PUCHAR)base,fName);
		if (addr == -1)
		{
			addr = (ULONG64)PeGetExportFuncAddr32((PUCHAR)base, fName);
		}
		KeUnstackDetachProcess(&apc);
		break;
	}
	
	ObDereferenceObject(proc);
	ExFreePool(mName);
	ExFreePool(fName);
	return addr;
}

ULONG64 mAddr[0x1000] = { 0 };
ULONG64 mSize[0x1000] = { 0 };

ULONG64 MmAllocateProcMemory(ULONG64 pid,ULONG64 size) {
	//修改内存属性
	ULONG64 oldProtect = NULL;
	pZwProtectVirtualMemory ProtectVirtualMemory = (pZwProtectVirtualMemory)KrGetVirtualProtectFuncAddr();
	if (!ProtectVirtualMemory)
	{
		return NULL;
	}
	ULONG64 mIndex = 0;
	for (ULONG64 i = 0; i < 0x1000; i++)
	{
		if (mAddr[i]==0) {
			mIndex = i;
			mSize[i] = 0;
			break;
		}
	}
	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return NULL;
	}

	ULONG64 s = size;
	ULONG64 base = NULL;
	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(proc,&apc);
	NTSTATUS status = ZwAllocateVirtualMemory(-1, &base, NULL, &s, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(proc);
		return NULL;
	}
	memset(base,0,s);
	ULONG64 baseP = base;
	ProtectVirtualMemory(-1, &baseP, &s, PAGE_EXECUTE_READ, &oldProtect);
	KeUnstackDetachProcess(&apc);
	mAddr[mIndex] = base;
	mSize[mIndex] = s;
	mIndex++;
	ObDereferenceObject(proc);
	return base;
}

BOOLEAN MmFreeProcMemory(ULONG64 pid, ULONG64 base) {
	ULONG64 tIndex = NULL;
	BOOLEAN needFree = FALSE;
	ULONG64 tBase = NULL;
	ULONG64 tSize = NULL;
	for (ULONG64 i = 0; i < 0x1000; i++)
	{
		if (mAddr[i] == base)
		{
			needFree = TRUE;
			tIndex = i;
			break;
		}
	}
	if (!needFree)
	{
		return FALSE;
	}
	tBase = base;
	tSize = mSize[tIndex];

	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return FALSE;
	}
	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(proc, &apc);
	ret = ZwFreeVirtualMemory(-1, &tBase, &tSize, MEM_RELEASE);
	//if (MmIsAddressValid(tBase))
	//{
	//	ret = ZwFreeVirtualMemory(-1, &tBase, &tSize, MEM_RELEASE);
	//}
	//else {
	//	ret = STATUS_UNSUCCESSFUL;
	//}
	KeUnstackDetachProcess(&apc);
	if (!NT_SUCCESS(ret))
	{
		ObDereferenceObject(proc);
		return FALSE;
	}
	mAddr[tIndex] = 0;
	mSize[tIndex] = 0;
	ObDereferenceObject(proc);
	return TRUE;
}

ULONG64 MmFindProcAddrBySignCode(ULONG64 pid,ULONG64 base,char* sign,ULONG64 len) {
	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return NULL;
	}
	PUCHAR n = (PUCHAR)ExAllocatePool(NonPagedPool,strlen(sign)+0x100);
	if (!n)
	{
		ObDereferenceObject(proc);
		return NULL;
	}
	memset(n, 0, strlen(sign) + 0x100);
	memcpy(n,sign, strlen(sign));
	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(proc,&apc);
	ULONG64 code = (ULONG64)MmFindAddrBySignCode(base, n,len);
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(proc);
	ExFreePool(n);
	return code;
}

ULONG64 PsGetPidByName(char* pname) {
	UNICODE_STRING string = { 0 };
	RtlInitUnicodeString(&string, L"PsGetProcessImageFileName");
	typedef PUCHAR(NTAPI* MyPsGetProcessImageFileName)(ULONG64 eproc);
	MyPsGetProcessImageFileName addr = (MyPsGetProcessImageFileName)MmGetSystemRoutineAddress(&string);
	if (!addr || !MmIsAddressValid(addr))
	{
		return NULL;
	}
	for (ULONG64 i = 0; i < 30000; i+=4)
	{
		PEPROCESS proc = NULL;
		NTSTATUS ret = PsLookupProcessByProcessId(i, &proc);
		if (!NT_SUCCESS(ret))
		{
			continue;
		}
		PUCHAR nameNow = addr(proc);
		if (nameNow && !strcmp(pname,nameNow))
		{
			ULONG offset = KrGetPidOffset();
			if (!offset)
			{
				return NULL;
			}
			return *(PULONG64)((PUCHAR)proc + offset);
		}
	}
	return NULL;
}

ULONG64 bpNameArr[20] = { 0 };
ULONG64 bpPidArr[20] = { 0 };
ULONG64 bpEprocArr[20] = { 0 };

VOID ByPassCallBack(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
) 
{
	PEPROCESS proc = NULL;
	NTSTATUS ret = PsLookupProcessByProcessId(ProcessId,&proc);
	if (!NT_SUCCESS(ret))
	{
		return;
	}
	UNICODE_STRING string = { 0 };
	RtlInitUnicodeString(&string, L"PsGetProcessImageFileName");
	typedef PUCHAR(NTAPI* MyPsGetProcessImageFileName)(ULONG64 eproc);
	MyPsGetProcessImageFileName addr = (MyPsGetProcessImageFileName)MmGetSystemRoutineAddress(&string);
	if (!addr || !MmIsAddressValid(addr))
	{
		return NULL;
	}
	char* imageName = (char*)addr(proc);
	for (ULONG64 i = 0; i < 20; i++)
	{
		if (bpNameArr[i] && !strcmp(bpNameArr[i], imageName))
		{
			bpPidArr[i] = ProcessId;
			PUCHAR newproc = (PUCHAR)ExAllocatePool(NonPagedPool, 0x1000);
			if (!newproc)
			{
				break;
			}
			memset(newproc, 0, 0x1000);
			memcpy(newproc, (PUCHAR)proc-48, 0x500);
			bpEprocArr[i] = (ULONG64)newproc+48;
			ExFreePool(bpNameArr[i]);
			bpNameArr[i] = 0;
			break;
		}
		if (!Create && bpPidArr[i]== ProcessId)
		{
			ExFreePool(bpEprocArr[i]-48);
			bpEprocArr[i] = 0;
			bpPidArr[i] = 0;
			break;
		}
	}
}


//BOOLEAN isFirstBypass = TRUE;
ULONG32 oldVersion = 0;
ULONG32 win11Version = 0x0F00055F0;
//破虚拟化
BOOLEAN PsVirtualByPass(char* pname) {
	if (MmIsAddressValid(pname) && strcmp(pname,"on")==0)
	{
		oldVersion = NtBuildNumber;
		return MmWriteKernelMemory(&NtBuildNumber,&win11Version,4);
	}
	else if(MmIsAddressValid(pname) && strcmp(pname, "off") == 0 && oldVersion!=0)
	{
		if (!MmWriteKernelMemory(&NtBuildNumber, &oldVersion, 4))
		{
			return FALSE;
		}
		oldVersion = 0;
		return TRUE;
	}
	return FALSE;
	//NTSTATUS ret = NULL;
	//if (!pname || !MmIsAddressValid(pname))
	//{
	//	return FALSE;
	//}
	//if (isFirstBypass)
	//{
	//	ret = PsSetCreateProcessNotifyRoutine(ByPassCallBack,FALSE);
	//	if (!NT_SUCCESS(ret))
	//	{
	//		return FALSE;
	//	}
	//	isFirstBypass = FALSE;
	//}
	//for (ULONG64 i = 0; i < 20; i++)
	//{
	//	if (!bpPidArr[i] && !bpNameArr[i] ) {
	//		PUCHAR t = (PUCHAR)ExAllocatePool(NonPagedPool,strlen(pname)+100);
	//		if (!t)
	//		{
	//			return FALSE;
	//		}
	//		memset(t,0, strlen(pname) + 100);
	//		memcpy(t,pname, strlen(pname));
	//		bpNameArr[i] = (ULONG64)t;
	//		return TRUE;
	//	}
	//}
	//return FALSE;
}



PEPROCESS GetBypassEprocess(ULONG64 pid) {
	for (ULONG64 i = 0; i < 20; i++)
	{
		if (bpPidArr[i] == pid)
		{
			return (PEPROCESS)bpEprocArr[i];
		}
	}
	return NULL;
}

BOOLEAN FsDeleteFile(char* path)
{
	OBJECT_ATTRIBUTES objFile = { 0 };
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioBlock = { 0 };
	UNICODE_STRING unFileName = { 0 };
	ANSI_STRING ansiPath = { 0 };
	RtlInitAnsiString(&ansiPath, path);
	RtlAnsiStringToUnicodeString(&unFileName,&ansiPath,TRUE);
	//RtlInitUnicodeString(&unFileName, path);
	InitializeObjectAttributes(&objFile, &unFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = ZwCreateFile(
		&hFile,
		GENERIC_READ,
		&objFile,
		&ioBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		RtlFreeUnicodeString(&unFileName);
		return FALSE;
	}

	PFILE_OBJECT pFile = NULL;

	status = ObReferenceObjectByHandle(hFile,
		FILE_ALL_ACCESS,
		*IoFileObjectType, KernelMode, &pFile, NULL);

	if (!NT_SUCCESS(status))
	{
		RtlFreeUnicodeString(&unFileName);
		ZwClose(hFile);
		return FALSE;
	}

	pFile->DeleteAccess = TRUE;
	pFile->DeletePending = FALSE;

	pFile->SectionObjectPointer->DataSectionObject = NULL;
	pFile->SectionObjectPointer->ImageSectionObject = NULL;
	//pFile->SectionObjectPointer->SharedCacheMap = NULL;

	ObDereferenceObject(pFile);
	ZwClose(hFile);

	status = ZwDeleteFile(&objFile);


	RtlFreeUnicodeString(&unFileName);

	return TRUE;
}


BOOLEAN HideProcessEx(ULONG64 srcPid, ULONG64 fakePid) {
	PEPROCESS srcProc = NULL;
	PEPROCESS fakeProc = NULL;
	NTSTATUS status = NULL;
	status = PsLookupProcessByProcessId(srcPid,&srcProc );
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	ObDereferenceObject(srcProc);
	status = PsLookupProcessByProcessId(fakePid ,&fakeProc);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	ObDereferenceObject(fakeProc);

	//1.清空EPROCESS->UniqueProcessId
	ULONG pidOffset = KrGetPidOffset();
	if (!pidOffset)
	{
		return FALSE;
	}
	*(PULONG64)((ULONG64)srcProc + pidOffset) = 0;
	
	//2.断EPROCESS->SessionProcessLinks  所有系统都是PID偏移+0x60
	PLIST_ENTRY sessionListEntry = (PLIST_ENTRY)((ULONG64)srcProc + pidOffset + 0x60);
	RemoveEntryList(sessionListEntry);
	sessionListEntry->Blink = sessionListEntry;
	sessionListEntry->Flink = sessionListEntry;
	
	//3.复制EPROCESS->ImageFileName
	ULONG imageFileNameOffset = KrGetImageFileNameOffset();
	if (!imageFileNameOffset)
	{
		return FALSE;
	}
	memcpy((PUCHAR)srcProc + imageFileNameOffset, (PUCHAR)fakeProc + imageFileNameOffset,15);
	
	//4.复制EPROCESS->ImagePathHash   所有系统都是imageFileName偏移+0x4C
	memcpy((PUCHAR)srcProc + imageFileNameOffset+0x4C, (PUCHAR)fakeProc + imageFileNameOffset + 0x4C, 4);
	
	//5.复制EPROCESS->SeAuditProcessCreationInfo  imageFileName偏移+  7：+B0    10：+18
	ULONG AdpcOffset = (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601) ? 0xB0 : 0x18;
	PUCHAR srcAdpcStr = *(PULONG64)((PUCHAR)srcProc + imageFileNameOffset + AdpcOffset);
	PUCHAR fakeAdpcStr = *(PULONG64)((PUCHAR)fakeProc + imageFileNameOffset + AdpcOffset);
	memcpy(srcAdpcStr, fakeAdpcStr, 8);
	PUCHAR newSrcAdpcStrBuf = (PUCHAR)ExAllocatePool(NonPagedPool,0x100);
	memset(newSrcAdpcStrBuf, 0, 0x100);
	memcpy(newSrcAdpcStrBuf, *(PULONG64)(fakeAdpcStr + 8), *(PUSHORT)(fakeAdpcStr));
	*(PULONG64)(srcAdpcStr + 8) = newSrcAdpcStrBuf;
	//if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	//{
	//	memcpy((PUCHAR)srcProc + imageFileNameOffset + 0xB0, (PUCHAR)fakeProc + imageFileNameOffset + 0xB0, 8);
	//}
	//else {
	//	memcpy((PUCHAR)srcProc + imageFileNameOffset + 0x18, (PUCHAR)fakeProc + imageFileNameOffset + 0x18, 8);
	//}
	
	//6.断EPROCESS->MmProcessLinks  蓝
	//7.复制EPROCESS->SectionObject pid偏移+  7：+E8    10：+D8
	//if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	//{
	//	memcpy((PUCHAR)srcProc + pidOffset + 0xE8, (PUCHAR)fakeProc + pidOffset + 0xE8, 8);
	//}
	//else {
	//	memcpy((PUCHAR)srcProc + pidOffset + 0xD8, (PUCHAR)fakeProc + pidOffset + 0xD8, 8);
	//}
	
	//8.复制EPROCESS->SectionBaseAddress
	if (VER_INFO.dwBuildNumber == 7600 || VER_INFO.dwBuildNumber == 7601)
	{
		memcpy((PUCHAR)srcProc + pidOffset + 0xE8+8, (PUCHAR)fakeProc + pidOffset + 0xE8 + 8, 8);
	}
	else {
		memcpy((PUCHAR)srcProc + pidOffset + 0xD8 + 8, (PUCHAR)fakeProc + pidOffset + 0xD8 + 8, 8);
	}
	//9.断KPROCESS->ProcessListEntry  蓝
	//===================处理PEB========================
	PPEB32 scrPeb32 = PsGetWow64ProcPeb32(srcProc);
	PPEB srcPeb64 = NULL;
	PPEB fakePeb64 = NULL;
	if (!scrPeb32)
	{
		return FALSE;
	}
	srcPeb64 = (PPEB)PsGetProcessPeb(srcProc);
	if (!srcPeb64)
	{
		return FALSE;
	}
	fakePeb64 = (PPEB)PsGetProcessPeb(fakeProc);
	if (!fakePeb64)
	{
		return FALSE;
	}
	KAPC_STATE apc = { 0 };
	//10.复制PEB->ImageBaseAddress  清空PE头
	pZwProtectVirtualMemory callZwProtectVirtualMemory = (pZwProtectVirtualMemory)KrGetVirtualProtectFuncAddr();
	if (!callZwProtectVirtualMemory)
	{
		return FALSE;
	}
	KeStackAttachProcess(srcProc,&apc);
	if (scrPeb32)
	{
		PULONG tempBase = scrPeb32->ImageBaseAddress;
		ULONG64 tempSize = 0x1000;
		ULONG oldProctect = NULL;
		status = callZwProtectVirtualMemory(-1,&tempBase,&tempSize,PAGE_READWRITE,&oldProctect);
		if (NT_SUCCESS(status))
		{
			memset(scrPeb32->ImageBaseAddress, 0, 0x1000);
		}
		callZwProtectVirtualMemory(-1, &tempBase, &tempSize, oldProctect, &oldProctect);
	}
	PULONG64 tempBase = *(PULONG64)((ULONG64)srcPeb64 + 0x10);
	ULONG64 tempSize = 0x1000;
	ULONG oldProctect = NULL;
	status = callZwProtectVirtualMemory(-1, &tempBase, &tempSize, PAGE_READWRITE, &oldProctect);
	if (NT_SUCCESS(status))
	{
		memset(*(PULONG64)((ULONG64)srcPeb64 + 0x10), 0, 0x1000);
	}
	callZwProtectVirtualMemory(-1, &tempBase, &tempSize, oldProctect, &oldProctect);
	KeUnstackDetachProcess(&apc);
	//11.复制PEB->ProcessParameters
	PUCHAR tempFakeNamePool = (PUCHAR)ExAllocatePool(NonPagedPool, 0x1000);
	if (!tempFakeNamePool)
	{
		return FALSE;
	}
	memset(tempFakeNamePool,0,0x1000);
	
	KeStackAttachProcess(fakeProc, &apc);
	ULONG64 pFakeProcessParam = *(PULONG64)((ULONG64)fakePeb64 + 0x20);
	
	ULONG64 pFakeProcCuurentDirUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0x38 + 0x8);
	USHORT pFakeProcCuurentDirUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0x38);
	USHORT pFakeProcCuurentDirUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0x38+2);
	
	ULONG64 pFakeProcDllPathUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0x50 + 0x8);
	USHORT pFakeProcDllPathUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0x50);
	USHORT pFakeProcDllPathUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0x50 + 2);
	
	ULONG64 pFakeProcImagePathNameUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0x60 + 0x8);
	USHORT pFakeProcImagePathNameUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0x60);
	USHORT pFakeProcImagePathNameUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0x60 + 2);
	
	ULONG64 pFakeProcCommandLineUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0x70 + 0x8);
	USHORT pFakeProcCommandLineUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0x70);
	USHORT pFakeProcCommandLineUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0x70 + 2);
	
	ULONG64 pFakeProcWindowTitleUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0xB0 + 0x8);
	USHORT pFakeProcWindowTitleUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0xB0);
	USHORT pFakeProcWindowTitleUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0xB0 + 2);
	
	ULONG64 pFakeProcDesktopInfoUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0xC0 + 0x8);
	USHORT pFakeProcDesktopInfoUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0xC0);
	USHORT pFakeProcDesktopInfoUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0xC0 + 2);
	
	ULONG64 pFakeProcShellInfoUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0xD0 + 0x8);
	USHORT pFakeProcShellInfoUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0xD0);
	USHORT pFakeProcShellInfoUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0xD0 + 2);
	
	ULONG64 pFakeProcRuntimeDataUnicodeStringBuffer = *(PULONG64)(pFakeProcessParam + 0xE0 + 0x8);
	USHORT pFakeProcRuntimeDataUnicodeStringLength = *(PUSHORT)(pFakeProcessParam + 0xE0);
	USHORT pFakeProcRuntimeDataUnicodeStringMaxLength = *(PUSHORT)(pFakeProcessParam + 0xE0 + 2);
	
	memcpy(tempFakeNamePool, pFakeProcCuurentDirUnicodeStringBuffer, pFakeProcCuurentDirUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x100, pFakeProcDllPathUnicodeStringBuffer, pFakeProcDllPathUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x200, pFakeProcImagePathNameUnicodeStringBuffer, pFakeProcImagePathNameUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x300, pFakeProcCommandLineUnicodeStringBuffer, pFakeProcCommandLineUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x400, pFakeProcWindowTitleUnicodeStringBuffer, pFakeProcWindowTitleUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x500, pFakeProcDesktopInfoUnicodeStringBuffer, pFakeProcDesktopInfoUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x600, pFakeProcShellInfoUnicodeStringBuffer, pFakeProcShellInfoUnicodeStringLength);
	memcpy(tempFakeNamePool + 0x700, pFakeProcRuntimeDataUnicodeStringBuffer, pFakeProcRuntimeDataUnicodeStringLength);
	KeUnstackDetachProcess(&apc);
	KeStackAttachProcess(srcProc, &apc);
	ULONG64 size = 0x1000;
	ULONG64 srcNewNameBufferPool = NULL;
	ZwAllocateVirtualMemory(-1,&srcNewNameBufferPool,NULL,&size, MEM_COMMIT, PAGE_READWRITE);
	if (srcNewNameBufferPool)
	{
		memcpy(srcNewNameBufferPool, tempFakeNamePool,0x1000);
	}
	if (scrPeb32)
	{
		//X86
		ULONG pSrcProcessParam = *(PULONG)((ULONG)scrPeb32 + 0x10);
		*(PUSHORT)(pSrcProcessParam + 0x24) = pFakeProcCuurentDirUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x24 + 2) = pFakeProcCuurentDirUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x30) = pFakeProcDllPathUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x30 + 2) = pFakeProcDllPathUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x38) = pFakeProcImagePathNameUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x38 + 2) = pFakeProcImagePathNameUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x40) = pFakeProcCommandLineUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x40 + 2) = pFakeProcCommandLineUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x70) = pFakeProcWindowTitleUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x70 + 2) = pFakeProcWindowTitleUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x78) = pFakeProcDesktopInfoUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x78 + 2) = pFakeProcDesktopInfoUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x80) = pFakeProcShellInfoUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x80 + 2) = pFakeProcShellInfoUnicodeStringMaxLength;
		*(PUSHORT)(pSrcProcessParam + 0x88) = pFakeProcRuntimeDataUnicodeStringLength;
		*(PUSHORT)(pSrcProcessParam + 0x88 + 2) = pFakeProcRuntimeDataUnicodeStringMaxLength;
		memset(*(PULONG)(pSrcProcessParam + 0x24 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x24));
		memset(*(PULONG)(pSrcProcessParam + 0x30 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x30));
		memset(*(PULONG)(pSrcProcessParam + 0x38 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x38));
		memset(*(PULONG)(pSrcProcessParam + 0x40 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x40));
		memset(*(PULONG)(pSrcProcessParam + 0x70 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x70));
		memset(*(PULONG)(pSrcProcessParam + 0x78 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x78));
		memset(*(PULONG)(pSrcProcessParam + 0x80 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x80));
		memset(*(PULONG)(pSrcProcessParam + 0x88 + 4), 0, *(PUSHORT)(pSrcProcessParam + 0x88));
		*(PULONG)(pSrcProcessParam + 0x24 + 4) = (ULONG)srcNewNameBufferPool;
		*(PULONG)(pSrcProcessParam + 0x30 + 4) = (ULONG)srcNewNameBufferPool+0x100;
		*(PULONG)(pSrcProcessParam + 0x38 + 4) = (ULONG)srcNewNameBufferPool+0x200;
		*(PULONG)(pSrcProcessParam + 0x40 + 4) = (ULONG)srcNewNameBufferPool+0x300;
		*(PULONG)(pSrcProcessParam + 0x70 + 4) = (ULONG)srcNewNameBufferPool+0x400;
		*(PULONG)(pSrcProcessParam + 0x78 + 4) = (ULONG)srcNewNameBufferPool+0x500;
		*(PULONG)(pSrcProcessParam + 0x80 + 4) = (ULONG)srcNewNameBufferPool+0x600;
		*(PULONG)(pSrcProcessParam + 0x88 + 4) = (ULONG)srcNewNameBufferPool+0x700;
	}
	//X64
	ULONG64 pSrcProcessX64Param = *(PULONG64)((ULONG64)srcPeb64 + 0x20);
	*(PUSHORT)(pSrcProcessX64Param + 0x38) = pFakeProcCuurentDirUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x38 + 2) = pFakeProcCuurentDirUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x50) = pFakeProcDllPathUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x50 + 2) = pFakeProcDllPathUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x60) = pFakeProcImagePathNameUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x60 + 2) = pFakeProcImagePathNameUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x70) = pFakeProcCommandLineUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0x70 + 2) = pFakeProcCommandLineUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xB0) = pFakeProcWindowTitleUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xB0 + 2) = pFakeProcWindowTitleUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xC0) = pFakeProcDesktopInfoUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xC0 + 2) = pFakeProcDesktopInfoUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xD0) = pFakeProcShellInfoUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xD0 + 2) = pFakeProcShellInfoUnicodeStringMaxLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xE0) = pFakeProcRuntimeDataUnicodeStringLength;
	*(PUSHORT)(pSrcProcessX64Param + 0xE0 + 2) = pFakeProcRuntimeDataUnicodeStringMaxLength;
	memset(*(PULONG64)(pSrcProcessX64Param + 0x38 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0x38));
	memset(*(PULONG64)(pSrcProcessX64Param + 0x50 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0x50));
	memset(*(PULONG64)(pSrcProcessX64Param + 0x60 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0x60));
	memset(*(PULONG64)(pSrcProcessX64Param + 0x70 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0x70));
	memset(*(PULONG64)(pSrcProcessX64Param + 0xB0 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0xB0));
	memset(*(PULONG64)(pSrcProcessX64Param + 0xC0 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0xC0));
	memset(*(PULONG64)(pSrcProcessX64Param + 0xD0 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0xD0));
	memset(*(PULONG64)(pSrcProcessX64Param + 0xE0 + 8), 0, *(PUSHORT)(pSrcProcessX64Param + 0xE0));
	*(PULONG64)(pSrcProcessX64Param + 0x38 + 8) = srcNewNameBufferPool;
	*(PULONG64)(pSrcProcessX64Param + 0x50 + 8) = srcNewNameBufferPool + 0x100;
	*(PULONG64)(pSrcProcessX64Param + 0x60 + 8) = srcNewNameBufferPool + 0x200;
	*(PULONG64)(pSrcProcessX64Param + 0x70 + 8) = srcNewNameBufferPool + 0x300;
	*(PULONG64)(pSrcProcessX64Param + 0xB0 + 8) = srcNewNameBufferPool + 0x400;
	*(PULONG64)(pSrcProcessX64Param + 0xC0 + 8) = srcNewNameBufferPool + 0x500;
	*(PULONG64)(pSrcProcessX64Param + 0xD0 + 8) = srcNewNameBufferPool + 0x600;
	*(PULONG64)(pSrcProcessX64Param + 0xE0 + 8) = srcNewNameBufferPool + 0x700;
	KeUnstackDetachProcess(&apc);
	ExFreePool(tempFakeNamePool);
	//12.复制PEB->pImageHeaderHash  太麻烦了
	//========================处理LDR_DATA_TABLE_ENTRY===================
	PUCHAR tempLdrNameBuffer = ExAllocatePool(NonPagedPool,0x200);
	if (!tempLdrNameBuffer)
	{
		return FALSE;
	}
	memset(tempLdrNameBuffer,0,0x200);

	KeStackAttachProcess(fakeProc,&apc);
	PPEB_LDR_DATA64 pFakeProcLdrData = (PPEB_LDR_DATA64)*(PULONG64)((ULONG64)fakePeb64 + 0x18);
	PLDR_DATA_TABLE_ENTRY64 pFakeProcLdrEntry = (PLDR_DATA_TABLE_ENTRY64)pFakeProcLdrData->InLoadOrderModuleList.Flink;

	USHORT FakeProcFullDllNameUnicodeStringLength = pFakeProcLdrEntry->FullDllName.Length;
	USHORT FakeProcFullDllNameUnicodeStringMaxLength = pFakeProcLdrEntry->FullDllName.MaximumLength;
	ULONG64 pFakeProcFullDllNameUnicodeStringBuffer = pFakeProcLdrEntry->FullDllName.Buffer;
	memcpy(tempLdrNameBuffer, pFakeProcFullDllNameUnicodeStringBuffer, FakeProcFullDllNameUnicodeStringLength);

	USHORT FakeProcBaseDllNameUnicodeStringLength = pFakeProcLdrEntry->BaseDllName.Length;
	USHORT FakeProcBaseDllNameUnicodeStringMaxLength = pFakeProcLdrEntry->BaseDllName.MaximumLength;
	ULONG64 pFakeProcBaseDllNameUnicodeStringBuffer = pFakeProcLdrEntry->BaseDllName.Buffer;
	memcpy(tempLdrNameBuffer+0x100, pFakeProcBaseDllNameUnicodeStringBuffer, FakeProcBaseDllNameUnicodeStringLength);
	KeUnstackDetachProcess(&apc);
	
	KeStackAttachProcess(srcProc, &apc);
	ULONG64 srcLdrBuffer = NULL;
	ULONG64 SrcLdrLen = 0x200;
	ZwAllocateVirtualMemory(-1,&srcLdrBuffer,NULL,&SrcLdrLen,MEM_COMMIT,PAGE_READWRITE);
	if (srcLdrBuffer)
	{
		memcpy(srcLdrBuffer, tempLdrNameBuffer,0x200);
	}

	if (scrPeb32)
	{
		//X86
		PPEB_LDR_DATA32 pSrcProcLdrData32 = (PPEB_LDR_DATA32)*(PULONG)((ULONG)scrPeb32 + 0xC);
		PLDR_DATA_TABLE_ENTRY32 pSrcProcLdrEntry32 = (PLDR_DATA_TABLE_ENTRY32)pSrcProcLdrData32->InLoadOrderModuleList.Flink;
		PLIST_ENTRY32 tempListEntry = (PLIST_ENTRY32)((ULONG)pSrcProcLdrEntry32 + 0x00);
		RemoveEntryList32(tempListEntry);
		tempListEntry->Blink = tempListEntry;
		tempListEntry->Flink = tempListEntry;

		tempListEntry = (PLIST_ENTRY32)((ULONG)pSrcProcLdrEntry32 + 0x8);
		RemoveEntryList32(tempListEntry);
		tempListEntry->Blink = tempListEntry;
		tempListEntry->Flink = tempListEntry;

		tempListEntry = (PLIST_ENTRY32)((ULONG)pSrcProcLdrEntry32 + 0x10);
		RemoveEntryList32(tempListEntry);
		tempListEntry->Blink = tempListEntry;
		tempListEntry->Flink = tempListEntry;

		memset(pSrcProcLdrEntry32->FullDllName.Buffer, 0, pSrcProcLdrEntry32->FullDllName.Length);
		memset(pSrcProcLdrEntry32->BaseDllName.Buffer,0, pSrcProcLdrEntry32->BaseDllName.Length);
		pSrcProcLdrEntry32->FullDllName.Length = FakeProcFullDllNameUnicodeStringLength;
		pSrcProcLdrEntry32->FullDllName.MaximumLength = FakeProcFullDllNameUnicodeStringMaxLength;
		pSrcProcLdrEntry32->FullDllName.Buffer = (ULONG)srcLdrBuffer;
		pSrcProcLdrEntry32->BaseDllName.Length = FakeProcBaseDllNameUnicodeStringLength;
		pSrcProcLdrEntry32->BaseDllName.MaximumLength = FakeProcBaseDllNameUnicodeStringMaxLength;
		pSrcProcLdrEntry32->BaseDllName.Buffer = (ULONG)srcLdrBuffer+0x100;
	}
	//X64
	PPEB_LDR_DATA64 pSrcProcLdrData64 = (PPEB_LDR_DATA64) * (PULONG64)((ULONG64)srcPeb64 + 0x18);
	PLDR_DATA_TABLE_ENTRY64 pSrcProcLdrEntry64 = (PLDR_DATA_TABLE_ENTRY64)pSrcProcLdrData64->InLoadOrderModuleList.Flink;

	PLIST_ENTRY tempListEntry = (PLIST_ENTRY)((ULONG64)pSrcProcLdrEntry64+0x00);
	RemoveEntryList64(tempListEntry);
	tempListEntry->Blink = tempListEntry;
	tempListEntry->Flink = tempListEntry;

	tempListEntry = (PLIST_ENTRY)((ULONG64)pSrcProcLdrEntry64 + 0x10);
	RemoveEntryList64(tempListEntry);
	tempListEntry->Blink = tempListEntry;
	tempListEntry->Flink = tempListEntry;

	tempListEntry = (PLIST_ENTRY)((ULONG64)pSrcProcLdrEntry64 + 0x20);
	RemoveEntryList64(tempListEntry);
	tempListEntry->Blink = tempListEntry;
	tempListEntry->Flink = tempListEntry;

	memset(pSrcProcLdrEntry64->FullDllName.Buffer, 0, pSrcProcLdrEntry64->FullDllName.Length);
	memset(pSrcProcLdrEntry64->BaseDllName.Buffer, 0, pSrcProcLdrEntry64->BaseDllName.Length);
	pSrcProcLdrEntry64->FullDllName.Length = FakeProcFullDllNameUnicodeStringLength;
	pSrcProcLdrEntry64->FullDllName.MaximumLength = FakeProcFullDllNameUnicodeStringMaxLength;
	pSrcProcLdrEntry64->FullDllName.Buffer = srcLdrBuffer;
	pSrcProcLdrEntry64->BaseDllName.Length = FakeProcBaseDllNameUnicodeStringLength;
	pSrcProcLdrEntry64->BaseDllName.MaximumLength = FakeProcBaseDllNameUnicodeStringMaxLength;
	pSrcProcLdrEntry64->BaseDllName.Buffer = srcLdrBuffer + 0x100;
	KeUnstackDetachProcess(&apc);
	ExFreePool(tempLdrNameBuffer);
	
	return TRUE;
}

NTSTATUS NTAPI NtGetNextThread(
	__in HANDLE ProcessHandle,
	__in HANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG HandleAttributes,
	__in ULONG Flags,
	__out PHANDLE NewThreadHandle
)
{

	typedef NTSTATUS(NTAPI* ZwGetNextThreadProc)(
		__in HANDLE ProcessHandle,
		__in HANDLE ThreadHandle,
		__in ACCESS_MASK DesiredAccess,
		__in ULONG HandleAttributes,
		__in ULONG Flags,
		__out PHANDLE NewThreadHandle
		);

	static ZwGetNextThreadProc ZwGetNextThreadFunc = NULL;
	if (!ZwGetNextThreadFunc)
	{
		UNICODE_STRING unName = { 0 };
		RtlInitUnicodeString(&unName, L"ZwGetNextThread");
		ZwGetNextThreadFunc = (ZwGetNextThreadProc)MmGetSystemRoutineAddress(&unName);
		if (!ZwGetNextThreadFunc)
		{
			UNICODE_STRING unName = { 0 };
			RtlInitUnicodeString(&unName, L"ZwGetNotificationResourceManager");
			PUCHAR ZwGetNotificationResourceManagerAddr = (PUCHAR)MmGetSystemRoutineAddress(&unName);
			ZwGetNotificationResourceManagerAddr -= 0x50;
			for (int i = 0; i < 0x30; i++)
			{
				if (ZwGetNotificationResourceManagerAddr[i] == 0x48
					&& ZwGetNotificationResourceManagerAddr[i + 1] == 0x8B
					&& ZwGetNotificationResourceManagerAddr[i + 2] == 0xC4)
				{
					ZwGetNextThreadFunc = ZwGetNotificationResourceManagerAddr + i;
					break;
				}
			}
		}
	}

	if (ZwGetNextThreadFunc)
	{
		return ZwGetNextThreadFunc(ProcessHandle, ThreadHandle, DesiredAccess,
			HandleAttributes, Flags, NewThreadHandle);
	}

	return STATUS_UNSUCCESSFUL;
}

PETHREAD NtGetProcessMainThread(PEPROCESS Process)
{
	PETHREAD ethread = NULL;

	KAPC_STATE kApcState = { 0 };

	KeStackAttachProcess(Process, &kApcState);

	HANDLE hThread = NULL;

	NTSTATUS status = NtGetNextThread(NtCurrentProcess(), NULL, THREAD_ALL_ACCESS,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &hThread);

	if (NT_SUCCESS(status))
	{

		status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS,
			*PsThreadType, KernelMode, &ethread, NULL);
		NtClose(hThread);

		if (!NT_SUCCESS(status))
		{
			ethread = NULL;
		}
	}


	KeUnstackDetachProcess(&kApcState);
	return ethread;
}










BOOLEAN MmReadProcessMemory_VirBypass(ULONG64 pid, ULONG64 dst, PUCHAR buf, ULONG64 len) {
	if (dst >= MmHighestUserAddress || (dst + len) > MmHighestUserAddress || dst < 0x1000)
	{
		return FALSE;
	}
	PEPROCESS proc = NULL;
	NTSTATUS ret = NULL;
	ret = PsLookupProcessByProcessId(pid, &proc);
	if (!NT_SUCCESS(ret))
	{
		return FALSE;
	}
	ObDereferenceObject(proc);
	
	PUCHAR bufR0 = (PUCHAR)ExAllocatePool(NonPagedPool, len+10);
	if (!bufR0)
	{
		return FALSE;
	}


	ULONG64 dstAlloc = dst;
	ULONG64 lenAlloc = len;
	BOOLEAN needFree = FALSE;
	//挂靠过去挂一下物理页
	KAPC_STATE apc = { 0 };
	KeStackAttachProcess(proc,&apc);
	ret = NtAllocateVirtualMemory(NtCurrentProcess(),&dstAlloc,NULL,&lenAlloc,MEM_COMMIT,PAGE_READWRITE);
	if (NT_SUCCESS(ret))
	{
		needFree = TRUE;
	}
	//else if (ret != STATUS_ALREADY_COMMITTED)
	//{
	//	KeUnstackDetachProcess(&apc);
	//	ExFreePool(myEthreadIncludeHeader);
	//	return FALSE;
	//}
	memcpy(bufR0, dst, 4);
	RtlZeroMemory(bufR0, len + 10);
	KeUnstackDetachProcess(&apc);

	PETHREAD dstThread = NtGetProcessMainThread(proc);
	if (!dstThread)
	{
		if (needFree)
		{
			KeStackAttachProcess(proc, &apc);
			NtFreeVirtualMemory(NtCurrentProcess(),&dstAlloc,NULL, MEM_RELEASE);
			KeUnstackDetachProcess(&apc);
		}
		ExFreePool(bufR0);
		return FALSE;
	}

	//备份自身线程结构
	PKTHREAD currentThread = KeGetCurrentThread();
	PUCHAR myEthreadIncludeHeader = (PUCHAR)ExAllocatePool(NonPagedPool, 0x500);
	if (!myEthreadIncludeHeader)
	{
		ExFreePool(bufR0);
		return FALSE;
	}
	RtlZeroMemory(myEthreadIncludeHeader, 0x500);
	


	//关中断
	_disable();
	//备份自身线程结构
	memcpy(myEthreadIncludeHeader, (PUCHAR)currentThread - 0x38, 0x500);
	//替换ETHREAD
	memcpy((PUCHAR)currentThread-0x38,(PUCHAR)dstThread-0x38,0x500);
	//切换CR3
	ULONG64 oldCr3 = __readcr3();
	__writecr3(*(PULONG64)((PUCHAR)proc + 0x28));
	memcpy(bufR0,dst,len);
	__writecr3(oldCr3);
	//恢复EPROCESS
	memcpy((PUCHAR)currentThread - 0x38, myEthreadIncludeHeader, 0x500);
	_enable();
	memcpy(buf, bufR0, len);
	ExFreePool(myEthreadIncludeHeader);
	ExFreePool(bufR0);
	if (needFree)
	{
		KeStackAttachProcess(proc, &apc);
		NtFreeVirtualMemory(NtCurrentProcess(), &dstAlloc, NULL, MEM_RELEASE);
		KeUnstackDetachProcess(&apc);
	}
	return TRUE;
}














