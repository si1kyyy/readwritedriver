#pragma once
#include "api.h"

//EXTERN_C NTSTATUS WINAPI Api_ComSend(ULONG64 cmd, ULONG64 inData, ULONG64 inLen, ULONG64 outData, ULONG64 outLen) {
//	return ComSend(cmd,  inData,  inLen,  outData,  outLen);
//}
//EXTERN_C BOOLEAN WINAPI Api_InitCom() {
//	return InitCom();
//}
EXTERN_C ULONG64 WINAPI Api_GetModuleBase(ULONG64 pid, char* name) {
	return GetModuleBase( pid, name);
}
EXTERN_C BOOLEAN WINAPI Api_ReadProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len, ULONG64 way) {
	return ReadProcMemory( pid,  dst,  buf,  len,  way);
}
EXTERN_C BOOLEAN WINAPI Api_WriteProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len) {
	return WriteProcMemory( pid,  dst,  buf,  len);
}
EXTERN_C BOOLEAN WINAPI Api_InitProcProtect() {
	return InitProcProtect();
}
EXTERN_C BOOLEAN WINAPI Api_UnloadProcProtect() {
	return UnloadProcProtect();
}
EXTERN_C BOOLEAN WINAPI Api_AddProcProtect(ULONG64 pid) {
	return AddProcProtect( pid);
}
EXTERN_C BOOLEAN WINAPI Api_RemoteCall(ULONG64 pid, ULONG64 tid, REMOTE_CALL_MODE mode, ULONG64 shellcode, ULONG64 len) {
	return RemoteCall( pid,  tid,  mode,  shellcode,  len);
}
EXTERN_C ULONG64 WINAPI Api_GetExpFuncAddrOfProcModule(ULONG64 pid, char* moduleName, char* funcName) {
	return GetExpFuncAddrOfProcModule(pid, moduleName, funcName);
}
EXTERN_C ULONG64 WINAPI Api_AllocaProcMemory(ULONG64 pid, ULONG64 size) {
	return AllocaProcMemory(pid, size);
}
EXTERN_C BOOLEAN WINAPI Api_FreeProcMemory(ULONG64 pid,ULONG64 base) {
	return FreeProcMemory(pid, base);
}
EXTERN_C ULONG64 WINAPI Api_FindProcSignCode(ULONG64 pid, ULONG64 base, ULONG64 sign, ULONG64 len) {
	return FindProcSignCode(pid, base,sign,len);
}
EXTERN_C BOOLEAN WINAPI Api_HideProcessByPid(ULONG64 pid,ULONG64 dstpid) {
	return HideProcessByPid(pid, dstpid);
}
EXTERN_C BOOLEAN WINAPI Api_UnloadDriver() {
	return UnloadDriver();
}
EXTERN_C BOOLEAN WINAPI Api_VirBypass(char* pname) {
	return VirBypass(pname);
}
EXTERN_C BOOLEAN WINAPI Api_DeleteFileForce(char* path) {
	return DeleteFileForce(path);
}
//EXTERN_C BOOLEAN WINAPI Api_TestCom() {
//	return TestCom();
//}
EXTERN_C BOOLEAN WINAPI Api_LoadDriver() {
	return LoadDriver();
}



EXTERN_C BOOLEAN WINAPI Api_KmInstall() {
	return KmInstall();
}

EXTERN_C BOOLEAN WINAPI Api_KmKeyDown(ULONG64 kVal) {
	return KmKeyDown(kVal);
}
EXTERN_C BOOLEAN WINAPI Api_KmKeyUp(ULONG64 kVal) {
	return KmKeyUp(kVal);
}

EXTERN_C BOOLEAN WINAPI Api_KmMouseLeftDown() {
	return KmMouseLeftDown();
}

EXTERN_C BOOLEAN WINAPI Api_KmMouseLeftUp() {
	return KmMouseLeftUp();
}

EXTERN_C BOOLEAN WINAPI Api_KmMouseRightDown() {
	return KmMouseRightDown();
}

EXTERN_C BOOLEAN WINAPI Api_KmMouseRightUp() {
	return KmMouseRightUp();
}

EXTERN_C BOOLEAN WINAPI Api_KmMouseMoveRelative(LONG64 dx, LONG64 dy) {
	return KmMouseMoveRelative(dx,dy);
}

EXTERN_C BOOLEAN WINAPI Api_KmMouseMoveTo(LONG64 dx, LONG64 dy) {
	return KmMouseMoveTo(dx,dy);
}