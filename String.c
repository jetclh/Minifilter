/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

	operations.c

Abstract:

	This is the support routines module of the kernel mode filter driver.

Environment:

	Kernel mode

--*/


#include "Include.h"


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, HiveAllocateUnicodeString)
#pragma alloc_text(PAGE, HiveFreeUnicodeString)
#endif

//
//  Support Routines
//

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _In_)
_At_(String->Buffer, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(String->MaximumLength))
NTSTATUS
HiveAllocateUnicodeString(
	_Out_ PUNICODE_STRING String,
	_In_ ULONG Tag
)
/*++

Routine Description:

This routine allocates a unicode string

Arguments:

String - supplies the size of the string to be allocated in the MaximumLength field
return the unicode string

Return Value:

STATUS_SUCCESS                  - success
STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{
	if (String->Buffer != NULL)
	{
		HiveFreeUnicodeString(String, Tag);
	}
	String->MaximumLength = MAX_PATH * sizeof(wchar_t) + 2;
	String->Buffer = ExAllocatePoolWithTag(NonPagedPool, String->MaximumLength, Tag);
	if (String->Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(String->Buffer, String->MaximumLength);
	String->Length = 0;

	return STATUS_SUCCESS;
}

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _Out_range_(== , 0))
_At_(String->Buffer, _Pre_notnull_ _Post_null_)
VOID
HiveFreeUnicodeString(
	_Pre_notnull_ PUNICODE_STRING String,
	_In_ ULONG Tag
)
/*++

Routine Description:

This routine frees a unicode string

Arguments:

String - supplies the string to be freed

Return Value:

None

--*/
{
	if (NULL != String->Buffer)
	{
		ExFreePoolWithTag(String->Buffer, Tag);
		String->Buffer = NULL;
	}
	String->MaximumLength	= 0;
	String->Length			= 0;
}

NTSTATUS
GetProcessFullName(
	PUNICODE_STRING pProcessName
)
{
	ULONG			retLen			= 0;
	ULONG			bufLen			= 0;
	PVOID			pBuffer			= NULL;
	NTSTATUS		status			= STATUS_SUCCESS;
	PUNICODE_STRING	uProcessName	= NULL;

	//获取函数指针
	if (NULL == ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (ZwQueryInformationProcess == NULL)
		{
			return STATUS_Query_Process_Failed;
		}
	}
	//获取进程名长度
	status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, NULL, 0, &retLen);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return status;
	}
	//判断进程名长度是否超过最大长度
	bufLen = retLen - sizeof(UNICODE_STRING);
	if (pProcessName->MaximumLength < bufLen)
	{
		pProcessName->Length = (USHORT)bufLen;
		return STATUS_BUFFER_OVERFLOW;
	}
	//申请Buffer
	pBuffer = ExAllocatePoolWithTag(PagedPool, retLen, HIVE_STRING_TAG);
	if (pBuffer == NULL)
	{
		return  STATUS_INSUFFICIENT_RESOURCES;
	}
	//获取进程名
	status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, pBuffer, retLen, &retLen);
	if (NT_SUCCESS(status))
	{
		uProcessName = (PUNICODE_STRING)pBuffer;
		RtlCopyUnicodeString(pProcessName, uProcessName);
	}
	ExFreePoolWithTag(pBuffer, HIVE_STRING_TAG);

	return  status;
}

NTSTATUS
HiveIsProcessAllowed(
	VOID
)
{
	ULONG			ulIndex			= 0;
	NTSTATUS		status			= STATUS_SUCCESS;
	UNICODE_STRING	uProcess;

	RtlZeroMemory(&uProcess, sizeof(UNICODE_STRING));

	status = HiveAllocateUnicodeString(&uProcess, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = GetProcessFullName(&uProcess);
	if (!NT_SUCCESS(status))
	{
		goto ProcessCleanUp;
	}
	for (ulIndex = 0; ulIndex < gFilterData.stAllowProcess.ulAllowedProcess; ulIndex++)
	{
		if (RtlEqualUnicodeString(&uProcess, &gFilterData.stAllowProcess.arrAllowedProcess[ulIndex], TRUE))
		{
			status = STATUS_SUCCESS;
			goto ProcessCleanUp;
		}
	}
	status = STATUS_ACCESS_DENIED;
ProcessCleanUp:
	HiveFreeUnicodeString(&uProcess, HIVE_STRING_TAG);

	return status;
}