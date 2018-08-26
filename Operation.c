/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

	Operation.c

Abstract:

	This is the i/o operations module of the kernel mode filter driver.

Environment:

	Kernel mode

--*/


#include "Include.h"


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CreatePreOperation)
#pragma alloc_text(PAGE, CreatePostOperation)
#pragma alloc_text(PAGE, ClosePreOperation)
#pragma alloc_text(PAGE, ClosePostOperation)
#pragma alloc_text(PAGE, ReadPreOperation)
#pragma alloc_text(PAGE, ReadPostOperation)
#pragma alloc_text(PAGE, WritePreOperation)
#pragma alloc_text(PAGE, WritePostOperation)
#pragma alloc_text(PAGE, QueryInfoPreOperation)
#pragma alloc_text(PAGE, QueryInfoPostOperation)
#pragma alloc_text(PAGE, SetInfoPreOperation)
#pragma alloc_text(PAGE, SetInfoPostOperation)
#pragma alloc_text(PAGE, CleanUpPreOperation)
#endif


FLT_PREOP_CALLBACK_STATUS
CreatePreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	USHORT			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	ULONG			ulOptions		= 0;
	BOOLEAN			bFilter			= FALSE;
	BOOLEAN			bAllow			= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	ULONG			ulSendLen		= sizeof(DRIVER_COMMAND);
	ULONG			ulReplyLen		= sizeof(USER_COMMAND);
	UNICODE_STRING	uParentDir;
	DRIVER_COMMAND	sendMsg;
	USER_COMMAND	replyMsg;
	
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));
	RtlZeroMemory(&sendMsg, sizeof(DRIVER_COMMAND));
	RtlZeroMemory(&replyMsg, sizeof(USER_COMMAND));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreCreateCleanup;
	}
	//Win10��ɾ������ֱ�Ӿܾ���������Setinfo����
	ulOptions = Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE;
	if (ulOptions != 0)
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Refuse to delete file when create, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCreateCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreCreateCleanup;
	}
	//û��¼ֱ�ӷ���
	if (!gFilterData.bLogIn)
	{
		Data->IoStatus.Status = STATUS_User_Not_Login;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Not login when PreCreate, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCreateCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PreCreate, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCreateCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڹ�����������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		if (ulTemp < gFilterData.stNetDisk.arrNetDisk[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stNetDisk.arrNetDisk[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stNetDisk.arrNetDisk[ulIndex], TRUE))
		{
			bFilter = TRUE;
			break;
		}
	}
	if (!bFilter)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreCreateCleanup;
	}
	//�ж��Ƿ���˽���
	if (IsFlagOn(gFilterData.lFlag, HIVE_FILTER_PROCESS))
	{
		status = HiveIsProcessAllowed();
		if (!NT_SUCCESS(status))
		{
			Data->IoStatus.Status = status;
			status = FLT_PREOP_COMPLETE;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Process is denied when PreCreate, file(%wZ)\n", &FltObjects->FileObject->FileName));
			goto PreCreateCleanup;
		}
	}
	//�򿪲���ֱ�ӷ���(����FILE_OPEN, ���п��ܽ������ļ�)
	ulOptions = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
	if (ulOptions == FILE_OPEN)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreCreateCleanup;
	}
	//�ж��ļ�·���Ƿ��ڰ�������
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			bAllow = TRUE;
			break;
		}
	}
	if (!bAllow)
	{
		Data->IoStatus.Status = STATUS_Create_Access_Lack;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: PreCreate access lack, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCreateCleanup;
	}
	//���͵���������
	uParentDir.Length  = FltObjects->FileObject->FileName.Length + 2;
	sendMsg.emMajorCmd = ENUM_HIVE_MAJOR_Create;
	sendMsg.ulFileSize = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;;
	memcpy(sendMsg.chFilePath, uParentDir.Buffer, uParentDir.Length);
	status = MyFltSendMessage((PVOID)&sendMsg, ulSendLen, (PVOID)&replyMsg, &ulReplyLen, NULL);
	if (replyMsg.emUserCmd == ENUM_USER_Create && NT_SUCCESS(status) && NT_SUCCESS(replyMsg.dwErrorCode))
	{
		Data->IoStatus.Status = STATUS_SUCCESS;
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allow to create file when PreCreate, file(%wZ)\n", &uParentDir));
	}
	else
	{
		Data->IoStatus.Status = replyMsg.dwErrorCode;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Refuse to create file when PreCreate, file(%wZ), status(0x%08x), error(0x%08x)\n", \
				&uParentDir, status, replyMsg.dwErrorCode));
	}
PreCreateCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return status;
}


FLT_POSTOP_CALLBACK_STATUS
CreatePostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags)
{
	USHORT			ulTemp			= 0;
	ULONG			ulOptions		= 0;
	ULONG			ulIndex			= 0;
	BOOLEAN			bFilter			= FALSE;
	BOOLEAN			bAllow			= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	UNICODE_STRING	uParentDir;
	
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));
	
	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		goto PostCreateCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		goto PostCreateCleanup;
	}
	//�ļ��в���ֱ�ӷ��У��Ҳ�֪ͨ�ϲ�
	ulOptions = Data->Iopb->Parameters.Create.Options;
	if (FlagOn(ulOptions, FILE_DIRECTORY_FILE))
	{
		goto PostCreateCleanup;
	}
	//�ļ��д򿪲���ֱ�ӷ���
	ulOptions = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
	if (ulOptions == FILE_OPEN)
	{
		goto PostCreateCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PostCreate, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PostCreateCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڹ�����������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		if (ulTemp < gFilterData.stNetDisk.arrNetDisk[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stNetDisk.arrNetDisk[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stNetDisk.arrNetDisk[ulIndex], TRUE))
		{
			bFilter = TRUE;
			break;
		}
	}
	if (!bFilter)
	{
		goto PostCreateCleanup;
	}
	//�ж��ļ�·���Ƿ��ڰ�������
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			bAllow = TRUE;
			break;
		}
	}
	if (!bAllow)
	{
		goto PostCreateCleanup;
	}
PostCreateCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
ClosePreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	USHORT			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	ULONG			ulOptions		= 0;
	BOOLEAN			bAllow			= FALSE;
	BOOLEAN			bDirectory		= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	ULONG			ulSendLen		= sizeof(DRIVER_COMMAND);
	ULONG			ulReplyLen		= 0;
	ULONG			ulFileLen		= sizeof(FILE_POSITION_INFORMATION);
	ULONG			ulFileRet		= 0;
	UNICODE_STRING	uParentDir;
	DRIVER_COMMAND	sendMsg;
	LARGE_INTEGER	lTimeOut;
	lTimeOut.QuadPart = 500;
	FILE_STANDARD_INFORMATION fileInfo;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));
	RtlZeroMemory(&sendMsg, sizeof(DRIVER_COMMAND));
	RtlZeroMemory(&fileInfo, sizeof(FILE_STANDARD_INFORMATION));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		goto PreCloseCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		goto PreCloseCleanup;
	}
	//�ļ���ֱ�ӷ���
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &bDirectory);
	if (!NT_SUCCESS(status) || bDirectory)
	{
		goto PreCloseCleanup;
	}
	//û��¼ֱ�ӷ���
	if (!gFilterData.bLogIn)
	{
		Data->IoStatus.Status = STATUS_User_Not_Login;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Not login when PreClose, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCloseCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PreClose, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCloseCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڰ�������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			bAllow = TRUE;
			break;
		}
	}
	if (!bAllow)
	{
		goto PreCloseCleanup;
	}
	//�жϵ�ǰ�ļ��Ƿ����ļ���Ϣ�б���
	uParentDir.Length = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
	{
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] != 0 &&
			RtlEqualUnicodeString(&uParentDir, &gFilterData.stFileInfo.arrFilePath[ulIndex], TRUE))
		{
			if (gFilterData.stFileInfo.status[ulIndex] != STATUS_SUCCESS)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("[HiveMiniFilter]: Cleanup file info when PreClose, file(%wZ), status(0x%08x)\n", \
						&uParentDir, gFilterData.stFileInfo.status[ulIndex]));
				CleanUpFileInfo(&uParentDir);
				goto PreCloseCleanup;
			}
			break;
		}
	}
	if (ulIndex < MAX_FILE_NUMBER)
	{//��������д�����Ϣ����������
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] == 3)
		{
			FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, (PVOID)&fileInfo, ulFileLen, FileStandardInformation, &ulFileRet);
			sendMsg.emMajorCmd = ENUM_HIVE_MAJOR_Close;
			sendMsg.ulFileSize = fileInfo.EndOfFile.QuadPart;
			memcpy(sendMsg.chFilePath, uParentDir.Buffer, uParentDir.Length);
			status = MyFltSendMessage((PVOID)&sendMsg, ulSendLen, NULL, &ulReplyLen, &lTimeOut);
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Send message when PreClose, file(%wZ), status(0x%08x)\n", &uParentDir, status));
			CleanUpFileInfo(&uParentDir);
		}
	}
PreCloseCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
ClosePostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
ReadPreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	USHORT			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	ULONG			ulOptions		= 0;
	BOOLEAN			bFilter			= FALSE;
	BOOLEAN			bDirectory		= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	UNICODE_STRING	uParentDir;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreReadCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreReadCleanup;
	}
	//�ļ���ֱ�ӷ���
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &bDirectory);
	if (!NT_SUCCESS(status) || bDirectory)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreReadCleanup;
	}
	//û��¼ֱ�ӷ���
	if (!gFilterData.bLogIn)
	{
		Data->IoStatus.Status = STATUS_User_Not_Login;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Not login when PreRead, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreReadCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PreRead, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreReadCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڹ�����������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		if (ulTemp < gFilterData.stNetDisk.arrNetDisk[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stNetDisk.arrNetDisk[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stNetDisk.arrNetDisk[ulIndex], TRUE))
		{
			bFilter = TRUE;
			break;
		}
	}
	if (!bFilter)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreReadCleanup;
	}
	//�жϵ�ǰ�ļ��Ƿ��ڰ�������
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			goto PreReadCleanup;
		}
	}
	Data->IoStatus.Status = STATUS_Read_Access_Lack;
	status = FLT_PREOP_COMPLETE;
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: Refuse to read file when PreRead, Name(%wZ), status(0x%08x)\n", \
			&FltObjects->FileObject->FileName, Data->IoStatus.Status));
PreReadCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return status;
}


FLT_POSTOP_CALLBACK_STATUS
ReadPostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
WritePreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	USHORT			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	USHORT			ulOptions		= 0;
	BOOLEAN			bFilter			= FALSE;
	BOOLEAN			bAllow			= FALSE;
	BOOLEAN			bDirectory		= TRUE;
	NTSTATUS		status			= STATUS_SUCCESS;
	UNICODE_STRING	uParentDir;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreWriteCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreWriteCleanup;
	}
	//�ļ���ֱ�ӷ���
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &bDirectory);
	if (!NT_SUCCESS(status) || bDirectory)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreWriteCleanup;
	}
	//û��¼ֱ�ӷ���
	if (!gFilterData.bLogIn)
	{
		Data->IoStatus.Status = STATUS_User_Not_Login;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Not login when PreWrite, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreWriteCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PreWrite, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreWriteCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڹ�����������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		if (ulTemp < gFilterData.stNetDisk.arrNetDisk[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stNetDisk.arrNetDisk[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stNetDisk.arrNetDisk[ulIndex], TRUE))
		{
			bFilter = TRUE;
			break;
		}
	}
	if (!bFilter)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreWriteCleanup;
	}
	//�жϵ�ǰ�ļ��Ƿ��ڰ�������
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			bAllow = TRUE;
			break;
		}
	}
	if (!bAllow)
	{
		Data->IoStatus.Status = STATUS_Write_Access_Lack;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: PreWrite access lack, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreWriteCleanup;
	}
	//�жϵ�ǰ�ļ��Ƿ����ļ���Ϣ�б���
	uParentDir.Length = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
	{
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] != 0 &&
			RtlEqualUnicodeString(&uParentDir, &gFilterData.stFileInfo.arrFilePath[ulIndex], TRUE))
		{
			if (gFilterData.stFileInfo.status[ulIndex] != STATUS_SUCCESS)
			{
				//��ֹ�ļ�д�룬ֱ�ӷ���
				Data->IoStatus.Status = gFilterData.stFileInfo.status[ulIndex];
				status = FLT_PREOP_COMPLETE;
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("[HiveMiniFilter]: Stop PreWrite, file(%wZ), status(0x%08x)\n", &uParentDir, Data->IoStatus.Status));
				goto PreWriteCleanup;
			}
			break;
		}
	}
	//��ǰ�ļ��Ѿ�������Ϣ�б��У�ֱ�ӷ���
	if (ulIndex < MAX_FILE_NUMBER)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreWriteCleanup;
	}
	//�����ļ���Ϣ�б�
	for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
	{
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] == 0)
		{
			status = HiveAllocateUnicodeString(&gFilterData.stFileInfo.arrFilePath[ulIndex], HIVE_STRING_TAG);
			if (!NT_SUCCESS(status))
			{
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				status = FLT_PREOP_COMPLETE;
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("[HiveMiniFilter]: Allocate pool failed when PreWrite, file(%wZ)\n", &uParentDir));
				goto PreWriteCleanup;
			}
			RtlAppendUnicodeToString(&gFilterData.stFileInfo.arrFilePath[ulIndex], L"\\");
			RtlAppendUnicodeStringToString(&gFilterData.stFileInfo.arrFilePath[ulIndex], &FltObjects->FileObject->FileName);
			gFilterData.stFileInfo.arrFilePath[ulIndex].Length	= FltObjects->FileObject->FileName.Length + 2;
			gFilterData.stFileInfo.ulFileSize[ulIndex]			= 0;
			gFilterData.stFileInfo.ulOperateType[ulIndex]		= 3;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Add File Info when PreWrite, file(%wZ), ulIndex(0x%08x)\n", &uParentDir, ulIndex));
			break;
		}
	}
	if (ulIndex >= MAX_FILE_NUMBER)
	{
		Data->IoStatus.Status = STATUS_Much_File_Number;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Too much files, can't add file info when PreWrite, file(%wZ)\n", &uParentDir));
	}
	else
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
PreWriteCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return status;
}


FLT_POSTOP_CALLBACK_STATUS
WritePostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	ULONG			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	BOOLEAN			bDirectory		= FALSE;
	BOOLEAN			bFilter			= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	ULONG			ulSendLen		= sizeof(DRIVER_COMMAND);
	ULONG			ulReplyLen		= 0;
	UNICODE_STRING	uParentDir;
	DRIVER_COMMAND	sendMsg;
	LARGE_INTEGER	lTimeOut;
	lTimeOut.QuadPart = 500;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));
	RtlZeroMemory(&sendMsg, sizeof(DRIVER_COMMAND));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		goto PostWriteCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulIndex = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulIndex != 0)
	{
		goto PostWriteCleanup;
	}
	//�ļ���ֱ�ӷ���
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &bDirectory);
	if (!NT_SUCCESS(status) || bDirectory)
	{
		goto PostWriteCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PostWrite, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PostWriteCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڹ�����������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		if (ulTemp < gFilterData.stNetDisk.arrNetDisk[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stNetDisk.arrNetDisk[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stNetDisk.arrNetDisk[ulIndex], TRUE))
		{
			bFilter = TRUE;
			break;
		}
	}
	if (!bFilter)
	{
		goto PostWriteCleanup;
	}
	//�жϵ�ǰ�ļ��Ƿ����ļ���Ϣ�б���
	uParentDir.Length = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
	{
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] != 0 &&
			RtlEqualUnicodeString(&uParentDir, &gFilterData.stFileInfo.arrFilePath[ulIndex], TRUE))
		{
			if (gFilterData.stFileInfo.status[ulIndex] != STATUS_SUCCESS)
			{
				//��ֹ�ļ�д�룬ֱ�ӷ���
				Data->IoStatus.Status = gFilterData.stFileInfo.status[ulIndex];
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("[HiveMiniFilter]: Stop PostWrite, file(%wZ), status(0x%08x)\n", &uParentDir, Data->IoStatus.Status));
				goto PostWriteCleanup;
			}
			break;
		}
	}
	//��ǰ�ļ�û������Ϣ�б��У����ش���
	if (ulIndex >= MAX_FILE_NUMBER)
	{
		Data->IoStatus.Status = STATUS_Much_File_Number;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: The writing file isn't belong file list when PostWrite, file(%wZ), ulIndex(0x%08x)\n", &uParentDir, ulIndex));
		goto PostWriteCleanup;
	}
	//�����ļ�д����Ϣ����������100M����һ�Σ�Windowsÿ��д���ݴ�СΪ1M��
	if (gFilterData.stFileInfo.ulFileSize[ulIndex] == 0 ||/* Data->Iopb->Parameters.Write.Length != 0x100000 ||*/
		(abs(Data->Iopb->Parameters.Write.ByteOffset.QuadPart - gFilterData.stFileInfo.ulFileSize[ulIndex]) > (100 * 1024 * 1024)))
	{
		gFilterData.stFileInfo.ulFileSize[ulIndex] = (Data->Iopb->Parameters.Write.Length + Data->Iopb->Parameters.Write.ByteOffset.QuadPart);
		sendMsg.emMajorCmd = ENUM_HIVE_MAJOR_Write;
		sendMsg.ulFileSize = gFilterData.stFileInfo.ulFileSize[ulIndex];
		memcpy(sendMsg.chFilePath, uParentDir.Buffer, uParentDir.Length);
		status = MyFltSendMessage((PVOID)&sendMsg, ulSendLen, NULL, &ulReplyLen, &lTimeOut);
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Send message when PostWrite, file(%wZ), status(0x%08x)\n", &uParentDir, status));
	}
PostWriteCleanup:
	//����
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
QueryInfoPreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
QueryInfoPostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
SetInfoPreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	USHORT			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	USHORT			ulOptions		= 0;
	BOOLEAN			bAllow			= FALSE;
	BOOLEAN			bFilter			= FALSE;
	BOOLEAN			bDirectory		= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	ULONG			ulSendLen		= sizeof(DRIVER_COMMAND);
	ULONG			ulReplyLen		= sizeof(USER_COMMAND);
	UNICODE_STRING	uParentDir;
	DRIVER_COMMAND	sendMsg;
	USER_COMMAND	replyMsg;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));
	RtlZeroMemory(&sendMsg, sizeof(DRIVER_COMMAND));
	RtlZeroMemory(&replyMsg, sizeof(USER_COMMAND));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreSetInfoCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreSetInfoCleanup;
	}
	//û��¼ֱ�ӷ���
	if (!gFilterData.bLogIn)
	{
		Data->IoStatus.Status = STATUS_User_Not_Login;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Not login when PreSetInfo, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreSetInfoCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PreSetInfo, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreSetInfoCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڹ�����������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		if (ulTemp < gFilterData.stNetDisk.arrNetDisk[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stNetDisk.arrNetDisk[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &gFilterData.stNetDisk.arrNetDisk[ulIndex], TRUE))
		{
			bFilter = TRUE;
			break;
		}
	}
	if (!bFilter)
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		goto PreSetInfoCleanup;
	}
	//�ж��Ƿ���˽���
	if (IsFlagOn(gFilterData.lFlag, HIVE_FILTER_PROCESS))
	{
		status = HiveIsProcessAllowed();
		if (!NT_SUCCESS(status))
		{
			Data->IoStatus.Status = status;
			status = FLT_PREOP_COMPLETE;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Process is denied when PreSetInfo, file(%wZ)\n", &FltObjects->FileObject->FileName));
			goto PreSetInfoCleanup;
		}
	}
	//�жϵ�ǰ�ļ��Ƿ��ڰ�������
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			bAllow = TRUE;
			break;
		}
	}
	uParentDir.Length = FltObjects->FileObject->FileName.Length + 2;
	switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
	{
	case FileDispositionInformation:
	{//ɾ��
		//���ڰ������ڣ��ܾ�ɾ��
		if (!bAllow)
		{
			Data->IoStatus.Status = STATUS_Delete_Access_Lack;
			status = FLT_PREOP_COMPLETE;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Delete access lack, file(%wZ)\n", &uParentDir));
			goto PreSetInfoCleanup;
		}
		//�ܾ�ɾ���ļ���
		status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &bDirectory);
		if (!NT_SUCCESS(status) || bDirectory)
		{
			Data->IoStatus.Status = STATUS_Delete_Directory_Lack;
			status = FLT_PREOP_COMPLETE;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Can't delete directory when PreSetInfo, file(%wZ), status(0x%08x)\n", &uParentDir, status));
			goto PreSetInfoCleanup;
		}
		//�����ļ�ɾ����Ϣ����������
		sendMsg.emMajorCmd = ENUM_HIVE_MAJOR_SetInfo;
		sendMsg.emMinorCmd = ENUM_HIVE_MINOR_Delete;
		memcpy(sendMsg.chFilePath, uParentDir.Buffer, uParentDir.Length);
		status = MyFltSendMessage((PVOID)&sendMsg, ulSendLen, (PVOID)&replyMsg, &ulReplyLen, NULL);
		if (replyMsg.emUserCmd == ENUM_USER_Delete && NT_SUCCESS(status) && NT_SUCCESS(replyMsg.dwErrorCode))
		{
			Data->IoStatus.Status = STATUS_SUCCESS;
			status = FLT_PREOP_COMPLETE;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Allow to delete file when PreSetInfo, file(%wZ)\n", &uParentDir));
			CleanUpFileInfo(&uParentDir);
		}
		else
		{
			Data->IoStatus.Status = replyMsg.dwErrorCode;
			status = FLT_PREOP_COMPLETE;
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Refuse to delete file when PreSetInfo, file(%wZ), status(0x%08x), dwErrorCode(0x%08x)\n", \
					&uParentDir, status, replyMsg.dwErrorCode));
		}
	}
	break;
	case FileRenameInformation:
	{//������
		Data->IoStatus.Status = STATUS_Rename_Access_Lack;
		status = FLT_PREOP_COMPLETE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Rename access lack, file(%wZ)\n", &uParentDir));
	}
	break;
	default:
	{
		status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	break;
	}
PreSetInfoCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return status;
}


FLT_POSTOP_CALLBACK_STATUS
SetInfoPostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
CleanUpPreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
	USHORT			ulTemp			= 0;
	ULONG			ulIndex			= 0;
	USHORT			ulOptions		= 0;
	BOOLEAN			bAllow			= FALSE;
	BOOLEAN			bDirectory		= FALSE;
	NTSTATUS		status			= STATUS_SUCCESS;
	ULONG			ulSendLen		= sizeof(DRIVER_COMMAND);
	ULONG			ulReplyLen		= 0;
	ULONG			ulFileLen		= sizeof(FILE_POSITION_INFORMATION);
	ULONG			ulFileRet		= 0;
	UNICODE_STRING	uParentDir;
	DRIVER_COMMAND	sendMsg;
	LARGE_INTEGER	lTimeOut;
	lTimeOut.QuadPart = 500;
	FILE_STANDARD_INFORMATION fileInfo;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlZeroMemory(&uParentDir, sizeof(UNICODE_STRING));
	RtlZeroMemory(&sendMsg, sizeof(DRIVER_COMMAND));
	RtlZeroMemory(&fileInfo, sizeof(FILE_STANDARD_INFORMATION));

	//�ж��Ƿ����
	if (!IsFlagOn(gFilterData.lFlag, HIVE_FILTER_GLOBAL))
	{
		goto PreCleanCleanup;
	}
	//PIPE�ļ�ֱ�ӷ���
	ulOptions = FltObjects->FileObject->Flags & FO_NAMED_PIPE;
	if (ulOptions != 0)
	{
		goto PreCleanCleanup;
	}
	//�ļ���ֱ�ӷ���
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &bDirectory);
	if (!NT_SUCCESS(status) || bDirectory)
	{
		goto PreCleanCleanup;
	}
	//û��¼ֱ�ӷ���
	if (!gFilterData.bLogIn)
	{
		Data->IoStatus.Status = STATUS_User_Not_Login;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Not login when PreCleanup, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCleanCleanup;
	}
	//�����ļ�·��
	status = HiveAllocateUnicodeString(&uParentDir, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Allocate pool failed when PreCleanup, file(%wZ)\n", &FltObjects->FileObject->FileName));
		goto PreCleanCleanup;
	}
	RtlAppendUnicodeToString(&uParentDir, L"\\");
	RtlAppendUnicodeStringToString(&uParentDir, &FltObjects->FileObject->FileName);
	//�жϵ�ǰ�ļ��Ƿ��ڰ�������
	ulTemp = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		if (ulTemp < gFilterData.stAllowData.arrAllowedPath[ulIndex].Length)
		{
			continue;
		}
		uParentDir.Length = gFilterData.stAllowData.arrAllowedPath[ulIndex].Length;
		if (RtlEqualUnicodeString(&uParentDir, &(gFilterData.stAllowData.arrAllowedPath[ulIndex]), TRUE))
		{
			bAllow = TRUE;
			break;
		}
	}
	if (!bAllow)
	{
		goto PreCleanCleanup;
	}
	//�жϵ�ǰ�ļ��Ƿ����ļ���Ϣ�б���
	uParentDir.Length = FltObjects->FileObject->FileName.Length + 2;
	for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
	{
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] != 0 &&
			RtlEqualUnicodeString(&uParentDir, &gFilterData.stFileInfo.arrFilePath[ulIndex], TRUE))
		{
			if (gFilterData.stFileInfo.status[ulIndex] != STATUS_SUCCESS)
			{
				CleanUpFileInfo(&uParentDir);
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("[HiveMiniFilter]: Cleanup file info when PreCleanup, file(%wZ), status(0x%08x)\n", &uParentDir, status));
				goto PreCleanCleanup;
			}
			break;
		}
	}
	if (ulIndex < MAX_FILE_NUMBER)
	{//��������д�����Ϣ����������
		if (gFilterData.stFileInfo.ulOperateType[ulIndex] == 3)
		{
			FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, (PVOID)&fileInfo, ulFileLen, FileStandardInformation, &ulFileRet);
			sendMsg.emMajorCmd = ENUM_HIVE_MAJOR_Close;
			sendMsg.ulFileSize = fileInfo.EndOfFile.QuadPart;
			memcpy(sendMsg.chFilePath, uParentDir.Buffer, uParentDir.Length);
			status = MyFltSendMessage((PVOID)&sendMsg, ulSendLen, NULL, &ulReplyLen, &lTimeOut);
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Send message when PreCleanup, file(%wZ), status(0x%08x)\n", &uParentDir, status));
			CleanUpFileInfo(&uParentDir);
		}
	}
PreCleanCleanup:
	//����
	uParentDir.Length = ulTemp;
	HiveFreeUnicodeString(&uParentDir, HIVE_STRING_TAG);

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

NTSTATUS 
MyFltSendMessage(
	PVOID SenderBuffer, 
	ULONG SenderBufferLength, 
	PVOID ReplyBuffer, 
	PULONG ReplyLength, 
	PLARGE_INTEGER Timeout)
{
	KIRQL		irqlTemp	= NULL;
	BOOLEAN		bLower		= FALSE;
	NTSTATUS	status		= STATUS_SUCCESS;

	irqlTemp = KeGetCurrentIrql();
	if (irqlTemp > APC_LEVEL)
	{
// 		KeLowerIrql(APC_LEVEL);
// 		bLower = TRUE;
		return STATUS_SUCCESS;
	}
	status = FltSendMessage(gFilterData.Filter, &gFilterData.ClientPort, SenderBuffer, SenderBufferLength, ReplyBuffer, ReplyLength, Timeout);
// 	if (bLower)
// 	{
// 		KfRaiseIrql(irqlTemp);
// 	}
	return status;
}
