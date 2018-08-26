/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

	Operations.c

Abstract:

	This is the callback function with the user.

Environment:

	Kernel mode

--*/


#include "Include.h"


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ConnectCallback)
#pragma alloc_text(PAGE, DisconnectCallback)
#pragma alloc_text(PAGE, MessageCallBack)
#endif


NTSTATUS
ConnectCallback(
	PFLT_PORT ClientPort,
	PVOID ServerPortCookie,
	PVOID ConnectionContext,
	ULONG SizeOfContext,
	PVOID * ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: ConnectCallback Entered\n"));

	ASSERT(gFilterData.ClientPort == NULL);
	ASSERT(gFilterData.UserProcess == NULL);

	gFilterData.ClientPort  = ClientPort;
	gFilterData.UserProcess = PsGetCurrentProcess();

	return STATUS_SUCCESS;
}


VOID
DisconnectCallback(
	PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: DisconnectCallback Entered\n"));

	//�ͷž��
	if (NULL != gFilterData.ClientPort && NULL != gFilterData.Filter) {

		FltCloseClientPort(gFilterData.Filter, &gFilterData.ClientPort);
		gFilterData.ClientPort = NULL;
	}
	CleanUpAllowPath();
	CleanUpAllowProcess();
	CleanUpFilterNetDisk();
	CleanUpFileInfo(NULL);
	gFilterData.bLogIn = FALSE;
	gFilterData.UserProcess = NULL;
}


NTSTATUS
MessageCallBack(
	PVOID ConnectionCookie,
	PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputBufferLength)
{
	USHORT				ulTemp		= 0;
	ULONG				ulIndex1	= 0;
	ULONG				ulIndex2	= 0;
	ULONG				ulConut		= 0;
	NTSTATUS			status		= STATUS_SUCCESS;
	PUSER_COMMAND		pUserCmd	= NULL;
	PUNIT_INFORMATION	pUnitInfo	= NULL;
	PPROC_INFORMATION	pProcInfo	= NULL;
	PFILTER_DISKINFO    pNetDisk	= NULL;
	UNICODE_STRING		uParentDir;

	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferSize);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));

	//�жϲ���ָ��
	if (InputBuffer == NULL) {

		return STATUS_INVALID_PARAMETER;
	}
	pUserCmd = ((PUSER_COMMAND)InputBuffer);
	//�����R3����������
	switch (pUserCmd->emUserCmd) {
	case ENUM_USER_UpdateAllowedPath:
	{//���°�����
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Update allowed path Begin\n"));
		//���������
		CleanUpAllowPath();
		//���°�����
		ulConut = pUserCmd->dwBufSize / sizeof(UNIT_INFORMATION);
		if (ulConut > MAX_ALLOWED_PATH)
		{
			ulConut = MAX_ALLOWED_PATH;
		}
		pUnitInfo = (PUNIT_INFORMATION)pUserCmd->pDataBuf;
		for (ulIndex1 = 0; ulIndex1 < ulConut; ulIndex1++)
		{
			//��������·��
			status = HiveAllocateUnicodeString(&gFilterData.stAllowData.arrAllowedPath[ulIndex1], HIVE_STRING_TAG);
			if (!NT_SUCCESS(status))
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			gFilterData.stAllowData.arrAllowedPath[ulIndex1].Length = (USHORT)(wcslen(pUnitInfo[ulIndex1].chFilePath) * sizeof(wchar_t));
			RtlCopyMemory(gFilterData.stAllowData.arrAllowedPath[ulIndex1].Buffer, pUnitInfo[ulIndex1].chFilePath, sizeof(wchar_t) * MAX_PATH);
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Update allowed path(%wZ)\n", &gFilterData.stAllowData.arrAllowedPath[ulIndex1]));
			//�����û���
			status = HiveAllocateUnicodeString(&gFilterData.stAllowData.arrUserName[ulIndex1], HIVE_STRING_TAG);
			if (!NT_SUCCESS(status))
			{
				HiveFreeUnicodeString(&gFilterData.stAllowData.arrAllowedPath[ulIndex1], HIVE_STRING_TAG);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			gFilterData.stAllowData.arrUserName[ulIndex1].Length = (USHORT)(wcslen(pUnitInfo[ulIndex1].chUserName) * sizeof(wchar_t));
			RtlCopyMemory(gFilterData.stAllowData.arrUserName[ulIndex1].Buffer, pUnitInfo[ulIndex1].chUserName, sizeof(wchar_t) * MAX_PATH);
			//��������
			status = HiveAllocateUnicodeString(&gFilterData.stAllowData.arrPassword[ulIndex1], HIVE_STRING_TAG);
			if (!NT_SUCCESS(status))
			{
				HiveFreeUnicodeString(&gFilterData.stAllowData.arrAllowedPath[ulIndex1], HIVE_STRING_TAG);
				HiveFreeUnicodeString(&gFilterData.stAllowData.arrUserName[ulIndex1], HIVE_STRING_TAG);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			gFilterData.stAllowData.arrPassword[ulIndex1].Length = (USHORT)(wcslen(pUnitInfo[ulIndex1].chPassword) * sizeof(wchar_t));
			RtlCopyMemory(gFilterData.stAllowData.arrPassword[ulIndex1].Buffer, pUnitInfo[ulIndex1].chPassword, sizeof(wchar_t) * MAX_PATH);
			gFilterData.stAllowData.ulAllowedpath++;
		}
		if (ulConut > 0 && pUnitInfo != NULL)
		{
			gFilterData.bLogIn = TRUE;
		}
		else
		{
			gFilterData.bLogIn = FALSE;
		}
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Update allowed path Success\n"));
	}
	break;
	case ENUM_USER_UpdateAllowedProcess:
	{//����������ʵĽ���
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Update allowed process Begin\n"));
		//���������
		CleanUpAllowProcess();
		//���°�����
		SetLongFlag(gFilterData.lFlag, HIVE_FILTER_PROCESS);
		ulConut = pUserCmd->dwBufSize / sizeof(PROC_INFORMATION);
		if (ulConut > MAX_ALLOWED_PROCESS)
		{
			ulConut = MAX_ALLOWED_PROCESS;
		}
		pProcInfo = (PPROC_INFORMATION)pUserCmd->pDataBuf;
		for (ulIndex1 = 0; ulIndex1 < ulConut; ulIndex1++)
		{
			//����������ʵĽ���
			status = HiveAllocateUnicodeString(&gFilterData.stAllowProcess.arrAllowedProcess[ulIndex1], HIVE_STRING_TAG);
			if (!NT_SUCCESS(status))
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			gFilterData.stAllowProcess.arrAllowedProcess[ulIndex1].Length = (USHORT)(wcslen(pProcInfo[ulIndex1].chProcess) * sizeof(wchar_t));
			RtlCopyMemory(gFilterData.stAllowProcess.arrAllowedProcess[ulIndex1].Buffer, pProcInfo[ulIndex1].chProcess, sizeof(wchar_t) * MAX_PATH);
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Update allowed process(%wZ)\n", &gFilterData.stAllowProcess.arrAllowedProcess[ulIndex1]));
			gFilterData.stAllowProcess.ulAllowedProcess++;
		}
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Update allowed process Success\n"));
	}
	break;
	case ENUM_USER_UpdateNetDisk:
	{//���¹��˵�����
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Update filter net disk Begin\n"));
		//���������
		CleanUpFilterNetDisk();
		//���°�����
		ulConut = pUserCmd->dwBufSize / sizeof(FILTER_DISKINFO);
		if (ulConut > MAX_FILTER_NETDISK)
		{
			ulConut = MAX_FILTER_NETDISK;
		}
		pNetDisk = (PFILTER_DISKINFO)pUserCmd->pDataBuf;
		for (ulIndex1 = 0; ulIndex1 < ulConut; ulIndex1++)
		{
			//����������ʵĽ���
			status = HiveAllocateUnicodeString(&gFilterData.stNetDisk.arrNetDisk[ulIndex1], HIVE_STRING_TAG);
			if (!NT_SUCCESS(status))
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			gFilterData.stNetDisk.arrNetDisk[ulIndex1].Length = (USHORT)(wcslen(pNetDisk[ulIndex1].chNetDisk) * sizeof(wchar_t));
			RtlCopyMemory(gFilterData.stNetDisk.arrNetDisk[ulIndex1].Buffer, pNetDisk[ulIndex1].chNetDisk, sizeof(wchar_t) * MAX_PATH);
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Update filter net disk(%wZ)\n", &gFilterData.stNetDisk.arrNetDisk[ulIndex1]));
			gFilterData.stNetDisk.ulNetDisk++;
		}
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Update filter net disk Success\n"));
	}
	break;
	case ENUM_USER_StopWrite:
	{
		status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
		if (!NT_SUCCESS(status))
		{
			goto MessageCleanUp;
		}
		RtlCopyMemory(uParentDir.Buffer, pUserCmd->pDataBuf, pUserCmd->dwBufSize);
		ulTemp = (USHORT)pUserCmd->dwBufSize;
		//�ж��ļ�·���Ƿ��ڰ�������
		for (ulIndex1 = 0; ulIndex1 < gFilterData.stAllowData.ulAllowedpath; ulIndex1++)
		{
			if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex1].Length)
			{
				continue;
			}
			uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex1].Length;
			if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stAllowData.arrAllowedPath[ulIndex1], TRUE))
			{
				//��ֹ���ļ�����д��
				uParentDir.Length = (USHORT)pUserCmd->dwBufSize;
				for (ulIndex2 = 0; ulIndex2 < MAX_FILE_NUMBER; ulIndex2++)
				{
					if (gFilterData.stFileInfo.ulOperateType[ulIndex2] != 0 &&
						RtlEqualUnicodeString(&uParentDir, &gFilterData.stFileInfo.arrFilePath[ulIndex2], TRUE))
					{
						gFilterData.stFileInfo.status[ulIndex2] = pUserCmd->dwErrorCode;
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
							("[HiveMiniFilter]: Edit File Status, file(%wZ), status(0x%08x)\n", &uParentDir, pUserCmd->dwErrorCode));
						break;
					}
				}
				break;
			}
		}
	}
	break;
	default:
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Unknown user command(0x%08x)\n", pUserCmd->emUserCmd));
	}
	break;
	}
MessageCleanUp:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return status;
}