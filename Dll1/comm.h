// dllmain.cpp : 定义 DLL 应用程序的入口点。
#pragma once
#include "stdio.h"
#include "stdlib.h"
#include "Windows.h"
#include "intrin.h"
#include <Urlmon.h>
#include <Wininet.h>

#pragma comment(lib,"Urlmon.lib")
#pragma comment(lib, "Wininet.lib")

typedef struct _IO_STATUS_BLOCK {
	union {
		ULONG Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _ComPackage {
	ULONG64 sign;
	ULONG64 cmd;
	ULONG64 inData;
	ULONG64 inLen;
	ULONG64 outData;
	ULONG64 outLen;
	ULONG64 status;
}ComPackage, * PComPackage;


typedef ULONG(WINAPI* NtQueryInformationFileProc)(
	__in HANDLE FileHandle,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__out_bcount(Length) PVOID FileInformation,
	__in ULONG Length,
	__in ULONG FileInformationClass);

typedef ULONG(WINAPI* pNtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(
	char a1,
	PUCHAR a2,
	PUCHAR a3,
	PUCHAR a4);
typedef enum _CMD {
	CMD_TEST,
	CMD_GET_MODULE_BASE,
	CMD_READ_MDL,
	CMD_READ_MDL_WITH_TRY,
	CMD_READ_ATTACH,
	CMD_READ_APICOPY,
	CMD_WRITE,
	CMD_READ_VIRBYPASS,
	CMD_INIT_PROC_PROTECT,
	CMD_ADD_PROC_PROTECT,
	CMD_UNLOAD_PROC_PROTECT,
	CMD_REMOTE_CALL,
	CMD_GET_PROC_ADDR,
	CMD_ALLOC_MEM,
	CMD_FREE_MEM,
	CMD_FIND_SIGN,
	CMD_HIDE_PROC,
	CMD_UNLOAD_DRIVER,
	CMD_BYPASS_VIRTUAL,
	CMD_DEL_FILE,

	CMD_KM_INSTALL,
	CMD_KM_KEY,
	CMD_KM_MOUSE
};

typedef enum _REMOTE_CALL_MODE {
	RCM_WOW64 = 0,
	RCM_X64 = 1
}REMOTE_CALL_MODE;

typedef struct _RemoteCallPackage {
	ULONG64 pid;
	ULONG64 tid;
	REMOTE_CALL_MODE mode;
	ULONG64 shellcode;
	ULONG64 codeLen;
}RemoteCallPackage, * PRemoteCallPackage;

typedef struct _FindSignPackage {
	ULONG64 base;
	ULONG64 code;
	ULONG64 len;
	ULONG64 pid;
}FindSignPackage, * PFindSignPackage;

NTSTATUS ComSend(ULONG64 cmd, ULONG64 inData, ULONG64 inLen, ULONG64 outData, ULONG64 outLen);

BOOLEAN InitCom();
BOOLEAN InitComWin7();
ULONG64 GetModuleBase(ULONG64 pid,char* name);
#define _IS_WOW64 sizeof(char*) == 4

BOOLEAN ReadProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len, ULONG64 way);

BOOLEAN WriteProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len);
BOOLEAN InitProcProtect();
BOOLEAN UnloadProcProtect();
BOOLEAN AddProcProtect(ULONG64 pid);
BOOLEAN RemoteCall(ULONG64 pid, ULONG64 tid, REMOTE_CALL_MODE mode, ULONG64 shellcode, ULONG64 len);
ULONG64 GetExpFuncAddrOfProcModule(ULONG64 pid, char* moduleName, char* funcName);
BOOLEAN TestCom();
BOOLEAN LoadDriver();
ULONG64 AllocaProcMemory(ULONG64 pid, ULONG64 size);
ULONG64 FreeProcMemory(ULONG64 pid, ULONG64 base);
ULONG64 FindProcSignCode(ULONG64 pid, ULONG64 base, ULONG64 sign, ULONG64 len);
BOOLEAN HideProcessByPid(ULONG64 pid, ULONG64 dstPid);
BOOLEAN UnloadDriver();
BOOLEAN VirBypass(char* pname);
BOOLEAN DeleteFileForce(char* path);