/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

	HiveMiniProc.h

Abstract:

	This is the header file defining the functions of the kernel mode filter driver.

Environment:

	Kernel mode

--*/


#include "HiveMiniStruct.h"


//
//  Functions implemented in Init.c
//

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
InstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
InstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID
InstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
InstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
Unload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

VOID
ContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

BOOLEAN
QueryGlobalParameters(
	__in PUNICODE_STRING  pRegistryPath
);


//
//  Functions implemented in Operation.c
//

//Pre-Create
FLT_PREOP_CALLBACK_STATUS
CreatePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Post-Create
FLT_POSTOP_CALLBACK_STATUS
CreatePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//Pre-Close
FLT_PREOP_CALLBACK_STATUS
ClosePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Post-Close
FLT_POSTOP_CALLBACK_STATUS
ClosePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//Pre-Read
FLT_PREOP_CALLBACK_STATUS
ReadPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Post-Read
FLT_POSTOP_CALLBACK_STATUS
ReadPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//Pre-Write
FLT_PREOP_CALLBACK_STATUS
WritePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Post-Write
FLT_POSTOP_CALLBACK_STATUS
WritePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//Pre-QueryInfo
FLT_PREOP_CALLBACK_STATUS
QueryInfoPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Post-QueryInfo
FLT_POSTOP_CALLBACK_STATUS
QueryInfoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//Pre-SetInfo
FLT_PREOP_CALLBACK_STATUS
SetInfoPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Post-SetInfo
FLT_POSTOP_CALLBACK_STATUS
SetInfoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//Pre-CleanUp
FLT_PREOP_CALLBACK_STATUS
CleanUpPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

//Send Message
NTSTATUS
MyFltSendMessage(
	_In_reads_bytes_(SenderBufferLength) PVOID SenderBuffer,
	_In_ ULONG SenderBufferLength,
	_Out_writes_bytes_opt_(*ReplyLength) PVOID ReplyBuffer,
	_Inout_opt_ PULONG ReplyLength,
	_In_opt_ PLARGE_INTEGER Timeout
);


//
//  Functions implemented in Callback.c
//

//Connect Callback
NTSTATUS
ConnectCallback(
	__in PFLT_PORT ClientPort,
	__in PVOID ServerPortCookie,
	__in_bcount(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
);

//Disconnect Callback
VOID
DisconnectCallback(
	__in_opt PVOID ConnectionCookie
);

//Message Callback
NTSTATUS
MessageCallBack(
	__in PVOID ConnectionCookie,
	__in_bcount_opt(InputBufferSize) PVOID InputBuffer,
	__in ULONG InputBufferSize,
	__out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	__in ULONG OutputBufferSize,
	__out PULONG ReturnOutputBufferLength
);


//
//  Functions implemented in context.c
//

NTSTATUS
FindOrCreateFileContext(
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ BOOLEAN CreateIfNotFound,
	_When_(CreateIfNotFound != FALSE, _In_) _When_(CreateIfNotFound == FALSE, _In_opt_) PUNICODE_STRING FileName,
	_Outptr_ PFILE_CONTEXT *StreamContext,
	_Out_opt_ PBOOLEAN ContextCreated
);

NTSTATUS
CreateFileContext(
	_In_ PUNICODE_STRING FileName,
	_Outptr_ PFILE_CONTEXT *StreamContext
);

NTSTATUS
UpdateNameInFileContext(
	_In_ PUNICODE_STRING DirectoryName,
	_Inout_ PFILE_CONTEXT StreamContext
);


//
//  Functions implemented in Cleanup.c
//

//Free allow path buffer
VOID
CleanUpAllowPath(
);

//Free allow process buffer
VOID
CleanUpAllowProcess(
);

//Free filter net disk
VOID
CleanUpFilterNetDisk(
);

//Free file info buffer
VOID
CleanUpFileInfo(PUNICODE_STRING pString
);


//
//  Functions implemented in support.c
//

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _In_)
_At_(String->Buffer, _Pre_maybenull_ _Post_notnull_ _Post_writable_byte_size_(String->MaximumLength))
NTSTATUS
HiveAllocateUnicodeString(
	_Out_ PUNICODE_STRING String,
	_In_ ULONG Tag
);

_At_(String->Length, _Out_range_(== , 0))
_At_(String->MaximumLength, _Out_range_(== , 0))
_At_(String->Buffer, _Pre_notnull_ _Post_null_)
VOID
HiveFreeUnicodeString(
	_Pre_notnull_ PUNICODE_STRING String,
	_In_ ULONG Tag
);

typedef NTSTATUS(*QUERY_INFO_PROCESS)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);

NTSTATUS
GetProcessFullName(
	_Inout_ PUNICODE_STRING pProcessName
);

NTSTATUS
HiveIsProcessAllowed(
	VOID
);


//
//  Resource support
//

FORCEINLINE
PERESOURCE
HiveAllocateResource(
	VOID
)
{
	return ExAllocatePoolWithTag(NonPagedPool,
		sizeof(ERESOURCE),
		HIVE_RESOURCE_TAG);
}

FORCEINLINE
VOID
HiveFreeResource(
	_In_ PERESOURCE Resource
)
{
	ExFreePoolWithTag(Resource,
		HIVE_RESOURCE_TAG);
}

FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
HiveAcquireResourceExclusive(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_)
	PERESOURCE Resource
)
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
		!ExIsResourceAcquiredSharedLite(Resource));

	KeEnterCriticalRegion();
	(VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);
}

FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
HiveAcquireResourceShared(
	_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_)
	PERESOURCE Resource
)
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	KeEnterCriticalRegion();
	(VOID)ExAcquireResourceSharedLite(Resource, TRUE);
}

FORCEINLINE
VOID
_Releases_lock_(_Global_critical_region_)
_Requires_lock_held_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
HiveReleaseResource(
	_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
	PERESOURCE Resource
)
{
	FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
		ExIsResourceAcquiredSharedLite(Resource));

	ExReleaseResourceLite(Resource);
	KeLeaveCriticalRegion();
}

EXTERN_C_END