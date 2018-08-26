/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

    HiveMiniInit.c

Abstract:

    This is the main module of the HiveMiniFilter miniFilter driver.

Environment:

    Kernel mode

--*/


#include "Include.h"


#if HIVE_DEBUG
ULONG gTraceFlags = PTDBG_TRACE_ROUTINES;
#else
ULONG gTraceFlags = 0;
#endif
//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#pragma alloc_text(PAGE, InstanceTeardownStart)
#pragma alloc_text(PAGE, InstanceTeardownComplete)
#pragma alloc_text(PAGE, Unload)
#endif


//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	0,
	CreatePreOperation,
	CreatePostOperation },

	{ IRP_MJ_CLOSE,
	0,
	ClosePreOperation,
	ClosePostOperation },

	{ IRP_MJ_READ,
	0,
	ReadPreOperation,
	ReadPostOperation },

	{ IRP_MJ_WRITE,
	0,
	WritePreOperation,
	WritePostOperation },

	{ IRP_MJ_QUERY_INFORMATION,
	0,
	QueryInfoPreOperation,
	QueryInfoPostOperation },

	{ IRP_MJ_SET_INFORMATION,
	0,
	SetInfoPreOperation,
	SetInfoPostOperation },

	{ IRP_MJ_CLEANUP,
	0,
	CleanUpPreOperation,
	NULL },

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_READ,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      HiveMiniFilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_PNP,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      HiveMiniFilterPreOperation,
      HiveMiniFilterPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_FILE_CONTEXT,
	0,
	ContextCleanup,
	FILE_CONTEXT_SIZE,
	HIVE_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),						//  Size
    FLT_REGISTRATION_VERSION,						//  Version
    0,												//  Flags
	ContextRegistration,							//  Context
    Callbacks,										//  Operation callbacks
	Unload,						                    //  MiniFilterUnload
    InstanceSetup,									//  InstanceSetup
	InstanceQueryTeardown,							//  InstanceQueryTeardown
	InstanceTeardownStart,							//  InstanceTeardownStart
	InstanceTeardownComplete,						//  InstanceTeardownComplete
    NULL,											//  GenerateFileName
    NULL,											//  GenerateDestinationFileName
    NULL											//  NormalizeNameComponent
};


NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PSECURITY_DESCRIPTOR sd = NULL;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: DriverEntry Entered\n"));

	//��ʼ������
	gFilterData.Filter		= NULL;
	gFilterData.ServerPort	= NULL;
	gFilterData.UserProcess = NULL;
	gFilterData.ClientPort	= NULL;
	gFilterData.lFlag		= 0;
	gFilterData.bLogIn		= FALSE;
	CleanUpAllowPath();
	CleanUpAllowProcess();
	CleanUpFilterNetDisk();
	CleanUpFileInfo(NULL);

	//ע��ص�
	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterData.Filter);

	if (!NT_SUCCESS(status)) {

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: FltRegisterFilter Failed, status(0x%08x)\n", status));

		return status;
	}
	//�����˿�  
	RtlInitUnicodeString(&uniString, MINISPY_PORT_NAME);

	//����ͨ�Ŷ˿�Ȩ�� ,ֻ�й���Ա��ϵͳ���̲��ܲ���  
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status)) {

		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);

		//����ͨ�Ŷ˿�,�����ö�Ӧ�Ļص�����  
		status = FltCreateCommunicationPort(gFilterData.Filter,
			&gFilterData.ServerPort,
			&oa,//���õ�����  
			NULL,
			ConnectCallback,	//��R3����ʱ�ص� ��Ҫ�Ǽ�¼R3�Ľ���ID��EPROCESS�Ա�Ź������� ���м�¼R3��ͨ�Ŷ˿�,����������ͨ�ŵ�ʱ����  
			DisconnectCallback,	//��R3����ʱ�ص� ��Ҫ�ǹر�R3�˿ں�����R3�Ľ�����ϢΪNULL  
			MessageCallBack,	//����R3�������� ����R3���µĹ���
			1);					//���һ����Ϊ1

		//���úú���Ҫ�ͷ�Ȩ�޵�����  
		FltFreeSecurityDescriptor(sd);

		if (NT_SUCCESS(status)) {

			//��ʼ����  
			status = FltStartFiltering(gFilterData.Filter);

			if (NT_SUCCESS(status)) {

				//��ȡע����е�ֵ
				if (QueryGlobalParameters(RegistryPath))
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("[HiveMiniFilter]: DriverEntry Success, ServerPort(0x%08x)\n", gFilterData.ServerPort));
					return STATUS_SUCCESS;
				}
				else
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("[HiveMiniFilter]: DriverEntry QueryGlobalParameters failed\n"));
				}
			}
			//ʧ����ر�ͨѶ�˿� 
			FltCloseCommunicationPort(gFilterData.ServerPort);
		}
	}
	//ʧ����ȡ��ע��
	FltUnregisterFilter(gFilterData.Filter);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: DriverEntry Failed, status(0x%08x)\n", status));

	return status;
}


NTSTATUS
InstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	PAGED_CODE();

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("[HiveMiniFilter]: InstanceSetup Entered\n") );

	if (VolumeDeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM) {

		return STATUS_FLT_DO_NOT_ATTACH;
	}
    return STATUS_SUCCESS;
}


NTSTATUS
InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
	PAGED_CODE();

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("[HiveMiniFilter]: InstanceQueryTeardown Entered\n") );

    return STATUS_SUCCESS;
}


VOID
InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
	PAGED_CODE();

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("[HiveMiniFilter]: InstanceTeardownStart Entered\n") );
}


VOID
InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
	PAGED_CODE();

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("[HiveMiniFilter]: InstanceTeardownComplete Entered\n") );
}


NTSTATUS
Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    PAGED_CODE();

	UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("[HiveMiniFilter]: Unload Entered\n") );

	CleanUpAllowPath();
	CleanUpAllowProcess();
	CleanUpFilterNetDisk();
	CleanUpFileInfo(NULL);
	gFilterData.bLogIn = FALSE;
	gFilterData.UserProcess = NULL;

	if (NULL != gFilterData.ServerPort) {
		FltCloseCommunicationPort(gFilterData.ServerPort);
		gFilterData.ServerPort = NULL;
	}

	if (NULL != gFilterData.Filter) {
		FltUnregisterFilter(gFilterData.Filter);
		gFilterData.Filter = NULL;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: Unload Succeed\n"));

    return STATUS_SUCCESS;
}

VOID
ContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	PFILE_CONTEXT pFileContext = NULL;

	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(ContextType);

	switch (ContextType) {

	case FLT_FILE_CONTEXT:
	{
		pFileContext = (PFILE_CONTEXT)Context;
		HiveFreeUnicodeString(&pFileContext->FileName, HIVE_CONTEXT_TAG);
	}
	break;
	}
}

BOOLEAN
QueryGlobalParameters(
	__in PUNICODE_STRING  pRegistryPath
)
{
	ULONG						uFilterProcess		= 0;
	NTSTATUS                    status				= STATUS_SUCCESS;
	UNICODE_STRING              uParamPath;
	RTL_QUERY_REGISTRY_TABLE    QueryTable[2];

	RtlZeroMemory(&uParamPath, sizeof(UNICODE_STRING));
	RtlZeroMemory(&QueryTable[0], sizeof(RTL_QUERY_REGISTRY_TABLE) * 2);

	//����ע���·��
	status = HiveAllocateUnicodeString(&uParamPath, HIVE_STRING_TAG);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	RtlCopyUnicodeString(&uParamPath, pRegistryPath);
	RtlAppendUnicodeToString(&uParamPath, PARAMETERS_KEY);
	//��ѯȫ�ֱ�־��1��Ҫ���ˣ�0��ȫ����Ȩ
	QueryTable[0].Flags			= RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
	QueryTable[0].Name			= L"FilterGlobal";
	QueryTable[0].EntryContext	= &uFilterProcess;
	status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, uParamPath.Buffer, &QueryTable[0], NULL, NULL);
	if (!NT_SUCCESS(status) || uFilterProcess == 0)
	{
		ClearLongFlag(gFilterData.lFlag, HIVE_FILTER_GLOBAL);
	}
	else
	{
		SetLongFlag(gFilterData.lFlag, HIVE_FILTER_GLOBAL);
	}
	//��ѯ���̹��˱�־��1��Ҫ���˽��̣�0�������˽��̡����̹��˱�־���ⲿ����
// 	QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
// 	QueryTable[0].Name = L"FilterProcess";
// 	QueryTable[0].EntryContext = &uFilterProcess;
// 	status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, uParamPath.Buffer, &QueryTable[0], NULL, NULL);
// 	if (!NT_SUCCESS(status) || uFilterProcess == 0)
// 	{
 		ClearLongFlag(gFilterData.lFlag, HIVE_FILTER_PROCESS);
// 	}
// 	else
// 	{
// 		SetLongFlag(gFilterData.lFlag, HIVE_FILTER_PROCESS);
// 	}
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("[HiveMiniFilter]: QueryGlobalParameters success, flag(0x%08x)\n", gFilterData.lFlag));

	return TRUE;
}