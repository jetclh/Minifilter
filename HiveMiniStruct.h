#pragma once

#ifndef		MAX_PATH
#define		MAX_PATH							260
#endif

extern ULONG gTraceFlags;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

#define		SetLongFlag(_F,_SF)					InterlockedOr(&(_F), (ULONG)(_SF))
#define		ClearLongFlag(_F,_SF)				InterlockedAnd(&(_F), ~((ULONG)(_SF)))
#define		IsFlagOn(_F,_SF)					((BOOLEAN)(FlagOn(_F,_SF) == _SF))

#define		MINISPY_PORT_NAME					L"\\SobeyMiniPort"				//�˿�����
#define		PARAMETERS_KEY						L"\\Configuration"				//����Key
#define		PTDBG_TRACE_ROUTINES				0x00000001						//���Ա�־
#define		HIVE_FILTER_GLOBAL					0x00000001						//ȫ�ֹ��˱�־
#define		HIVE_FILTER_PROCESS					0x00000002						//���̹��˱�־
#define		MAX_ALLOWED_PROCESS					256								//������ʽ��̵�������
#define		MAX_ALLOWED_PATH					256								//������������
#define		MAX_FILTER_NETDISK					256								//��������������
#define		MAX_FILE_NUMBER						256								//ͬʱд�ļ�������
#define		HIVE_STRING_TAG						'HSxC'							//����Tag
#define		HIVE_CONTEXT_TAG					'HCxC'							//����Tag
#define		HIVE_RESOURCE_TAG					'HRxC'							//����Tag

//�������������
#define		STATUS_User_Not_Login				((NTSTATUS)0xE0003301L)			//�û�δ��¼
#define		STATUS_Create_Access_Lack			((NTSTATUS)0xE0003302L)			//û��CreateȨ��
#define		STATUS_Write_Access_Lack			((NTSTATUS)0xE0003303L)			//û��WriteȨ��
#define		STATUS_Read_Access_Lack				((NTSTATUS)0xE0003304L)			//û��ReadȨ��
#define		STATUS_Rename_Access_Lack			((NTSTATUS)0xE0003305L)			//û��RenameȨ��
#define		STATUS_Delete_Access_Lack			((NTSTATUS)0xE0003306L)			//û��DeleteȨ��
#define		STATUS_Delete_Directory_Lack		((NTSTATUS)0xE0003307L)			//û��ɾ���ļ��е�Ȩ��
#define		STATUS_Rename_Directory_Lack		((NTSTATUS)0xE0003308L)			//û���������ļ��е�Ȩ��
#define		STATUS_Is_Directory_Failed			((NTSTATUS)0xE0003309L)			//�ж��Ƿ��ļ���ʱʧ��
#define		STATUS_Much_File_Number				((NTSTATUS)0xE000330AL)			//��ǰ���ļ���������
#define		STATUS_Server_Exception				((NTSTATUS)0xE000330BL)			//�ӿڷ����쳣
#define		STATUS_Unknown_Interface			((NTSTATUS)0xE000330CL)			//δ֪�Ľӿڵ���
#define		STATUS_Query_Process_Failed			((NTSTATUS)0xE000330DL)			//��ѯ������ʧ��

//Hive�������������
#define		STATUS_Internal_Error				((NTSTATUS)0xE0000001L)			//ϵͳ�ڲ�����																1
#define		STATUS_Invalid_Pool 				((NTSTATUS)0xE0000065L)			//POOL��Ч(����֤�Ƿ���ڸ�POOL,����֤�û���POOL�Ĺ�ϵ)						101
#define		STATUS_Pool_Access_Lack				((NTSTATUS)0xE0000066L)			//POOL������UNIT������(�ռ���������õ�UNIT)								102
#define		STATUS_Invalid_FilePath				((NTSTATUS)0xE0000067L)			//�ļ�·����Ч																103
#define		STATUS_Invalid_FileSize				((NTSTATUS)0xE0000069L)			//�ļ���С��Ч																105
#define		STATUS_UnitBuffer_Lack				((NTSTATUS)0xE000006AL)			//Unit�ռ�������д��ʧ��													106
#define		STATUS_File_Not_Exist				((NTSTATUS)0xE000006BL)			//�����ļ�������															107
#define		STATUS_No_File_Record				((NTSTATUS)0xE000006CL)			//�����ļ�·��δ��ѯ���ļ���¼												108
#define		STATUS_File_Status_Error			((NTSTATUS)0xE000006DL)			//�ļ�״̬����																109
#define		STATUS_File_Already_Exist			((NTSTATUS)0xE000006EL)			//�ļ��Ѵ���																110
#define		STATUS_Record_Not_Exist				((NTSTATUS)0xE000006FL)			//�ļ���¼������															111
#define		STATUS_Analyze_File_Failed			((NTSTATUS)0xE000007DL)			//�����ļ�·��ʧ��															125
#define		STATUS_Get_FileSzie_Failed			((NTSTATUS)0xE000007EL)			//��ȡ�ļ���Сʧ��:[����SSHUtilʧ��]										126
#define		STATUS_Unknown_Record				((NTSTATUS)0xE000012DL)			//ɾ���ļ�ʧ��,δ��ѯ���ļ���¼												301
#define		STATUS_Delete_File_Failed			((NTSTATUS)0xE0000132L)			//ɾ�������ļ�ʧ��															306
#define		STATUS_File_In_Use					((NTSTATUS)0xE0000135L)			//ɾ���ļ�ʧ��,�ļ���ʹ��													309
#define		STATUS_Delete_Record_Failed			((NTSTATUS)0xE0000137L)			//ɾ���ļ�ʧ��,ɾ��FileRecord��¼ʧ��										311
#define		STATUS_Access_Lack					((NTSTATUS)0xE0002714L)			//û��Ȩ�޷���																10001
#define		STATUS_System_Error					((NTSTATUS)0xE0002715L)			//�ܾ�����,ϵͳ��δע������ϵͳ��������									10002
#define		STATUS_UserToken_Is_Null			((NTSTATUS)0xE0002714L)			//�ܾ�����,User Token����Ϊ��												10003
#define		STATUS_Invalid_UserToken			((NTSTATUS)0xE0002715L)			//�ܾ�����,User Token��Ч													10004
#define		STATUS_Invalide_Signature			((NTSTATUS)0xE0002714L)			//�ܾ�����,ϵͳ��֤ǩ����Ч													10005
#define		STATUS_System_Forbidden				((NTSTATUS)0xE0002715L)			//�ܾ�����,��ǰϵͳ�ѱ�����													10006
#define		STATUS_No_User_Info					((NTSTATUS)0xE0002714L)			//������δ��ȡ���û���Ϣ													10007
#define		STATUS_SiteID_Error					((NTSTATUS)0xE0002715L)			//�ܾ����ʣ�վ����δע������վ����������								10008
#define		STATUS_UserToken_Overdue			((NTSTATUS)0xE0002714L)			//�ܾ����ʣ�User Token�ѹ��ڣ��ѱ����										10009
#define		STATUS_Differ_SiteID				((NTSTATUS)0xE0002715L)			//�ܾ����ʣ���ǰ����վ������֤ʱվ�㲻��									10010
#define		STATUS_Unsupport_Interface			((NTSTATUS)0xE0002714L)			//�ܾ�����,����ӿڲ�֧��ϵͳǩ����֤										10011

//  Defines the major commands between the utility and the filter
typedef enum _HIVE_MAJOR_COMMAND
{
	ENUM_HIVE_MAJOR_Create = 1,
	ENUM_HIVE_MAJOR_Read,
	ENUM_HIVE_MAJOR_Write,
	ENUM_HIVE_MAJOR_Close,
	ENUM_HIVE_MAJOR_CleanUp,
	ENUM_HIVE_MAJOR_QueryInfo,
	ENUM_HIVE_MAJOR_SetInfo,
	ENUM_HIVE_MAJOR_DirectoryCtl,

} HIVE_MAJOR_COMMAND;

//  Defines the minor commands between the utility and the filter
typedef enum _HIVE_MINOR_COMMAND
{
	ENUM_HIVE_MINOR_Delete = 1,
	ENUM_HIVE_MINOR_Rename,
	ENUM_HIVE_MINOR_SetEndOfFile,

} HIVE_MINOR_COMMAND;

//  Defines the user commands between the utility and the filter
typedef enum _HIVE_USER_COMMAND
{
	ENUM_USER_UpdateAllowedPath = 1,
	ENUM_USER_UpdateAllowedProcess,
	ENUM_USER_UpdateNetDisk,
	ENUM_USER_StopWrite,
	ENUM_USER_Create,
	ENUM_USER_Read,
	ENUM_USER_Close,
	ENUM_USER_Delete,
	ENUM_USER_Rename,

} HIVE_USER_COMMAND;

//  Defines the allow path
typedef struct _ALLOW_PATH
{
	// Allow path array
	UNICODE_STRING arrAllowedPath[MAX_ALLOWED_PATH];

	// User name for allow path 
	UNICODE_STRING arrUserName[MAX_ALLOWED_PATH];

	// Password for allow path 
	UNICODE_STRING arrPassword[MAX_ALLOWED_PATH];

	// Allow path number
	ULONG ulAllowedpath;

}ALLOW_PATH, *PALLOW_PATH;

//  Defines the allow process
typedef struct _ALLOW_PROCESS
{
	// Allow process
	UNICODE_STRING arrAllowedProcess[MAX_ALLOWED_PROCESS];

	// Allow process number
	ULONG ulAllowedProcess;

}ALLOW_PROCESS, *PALLOW_PROCESS;

//  Defines the filter net disk
typedef struct _FILTER_NETDISK
{
	// Filter net disk 
	UNICODE_STRING arrNetDisk[MAX_FILTER_NETDISK];

	// Filter net disk number
	ULONG ulNetDisk;

}FILTER_NETDISK, *PFILTER_NETDISK;

//  Defines the file info
typedef struct _FILTER_FILE_INFO
{
	// File path
	UNICODE_STRING arrFilePath[MAX_FILE_NUMBER];

	// File size
	ULONGLONG ulFileSize[MAX_FILE_NUMBER];

	// Operate type(0:not user, 1:create, 2:read, 3:write, 4:close)
	ULONG ulOperateType[MAX_FILE_NUMBER];

	// File status(0:normal, other:forbidden(error code))
	NTSTATUS status[MAX_FILE_NUMBER];

}FILTER_FILE_INFO, PFILTER_FILE_INFO;

//  Defines the global parameters
typedef struct _FILTER_DATA {

	//  The object that identifies this driver.
	PDRIVER_OBJECT DriverObject;

	//  The filter handle that results from a call to FltRegisterFilter
	PFLT_FILTER Filter;

	//  Listens for incoming connections
	PFLT_PORT ServerPort;

	//  User process that connected to the port
	PEPROCESS UserProcess;

	//  Client port for a connection to user-mode
	PFLT_PORT ClientPort;

	//  Allow path
	ALLOW_PATH stAllowData;

	//  Allow process
	ALLOW_PROCESS stAllowProcess;

	// Filter net disk
	FILTER_NETDISK stNetDisk;

	//  Filter file info
	FILTER_FILE_INFO stFileInfo;

	// Global flags for the driver
	LONG lFlag;

	// LogIn flag
	BOOLEAN bLogIn;

} FILTER_DATA, *PFILTER_DATA;

//  Defines the file context
typedef struct _FILE_CONTEXT {

	// The FileObject that is the target for this IO operation.
	PFILE_OBJECT FileObject;

	//  Instance that i/o is directed to
	PFLT_INSTANCE Instance;

	// Name of the file associated with this context.
	UNICODE_STRING FileName;

	// File size
	ULONGLONG ulFileSize;

	// Read number
	ULONG ulReadCnt;

	// Write number
	ULONG ulWriteCnt;

	// File status(0:normal, other:forbidden(error code))
	NTSTATUS status;

	// Lock used to protect this context.
	PERESOURCE Resource;

}FILE_CONTEXT, *PFILE_CONTEXT;

#define FILE_CONTEXT_SIZE	sizeof(FILE_CONTEXT)

//  Defines the user command structure.
typedef struct _USER_COMMAND
{
	HIVE_USER_COMMAND  		emUserCmd;				//  user command type
	NTSTATUS				dwErrorCode;			//  my error code
	unsigned long			dwBufSize;				//  sizeof(data)
	PVOID					pDataBuf;				//  data
	ULONGLONG				ulReserve;				//  reserve

} USER_COMMAND, *PUSER_COMMAND;

//  Defines the driver command structure.
typedef struct _DRIVER_COMMAND
{
	HIVE_MAJOR_COMMAND  	emMajorCmd;				//  major command type
	HIVE_MINOR_COMMAND		emMinorCmd;				//  minor command type
	wchar_t					chFilePath[260];		//  file full path
	wchar_t					chRename[260];			//  file full path for rename operation
	NTSTATUS				dwErrorCode;			//  my error code
	ULONGLONG				ulFileSize;				//  file size when write, create options when create
	ULONGLONG				ulMessageID;			//  message id
	ULONGLONG				ulReserve;				//  reserve

} DRIVER_COMMAND, *PDRIVER_COMMAND;

//����Unit��Ϣ
typedef struct _UNIT_INFORMATION
{
	wchar_t		chFilePath[MAX_PATH];
	wchar_t		chUserName[MAX_PATH];
	wchar_t		chPassword[MAX_PATH];

}UNIT_INFORMATION, *PUNIT_INFORMATION;

//����Process��Ϣ
typedef struct _PROC_INFORMATION
{
	wchar_t		chProcess[MAX_PATH];

}PROC_INFORMATION, *PPROC_INFORMATION;

//����Process��Ϣ
typedef struct _FILTER_DISKINFO
{
	wchar_t		chNetDisk[MAX_PATH];

}FILTER_DISKINFO, *PFILTER_DISKINFO;