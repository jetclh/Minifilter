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

#define		MINISPY_PORT_NAME					L"\\SobeyMiniPort"				//端口名称
#define		PARAMETERS_KEY						L"\\Configuration"				//参数Key
#define		PTDBG_TRACE_ROUTINES				0x00000001						//调试标志
#define		HIVE_FILTER_GLOBAL					0x00000001						//全局过滤标志
#define		HIVE_FILTER_PROCESS					0x00000002						//进程过滤标志
#define		MAX_ALLOWED_PROCESS					256								//允许访问进程的最大个数
#define		MAX_ALLOWED_PATH					256								//白名单最大个数
#define		MAX_FILTER_NETDISK					256								//过滤网盘最大个数
#define		MAX_FILE_NUMBER						256								//同时写文件最大个数
#define		HIVE_STRING_TAG						'HSxC'							//缓冲Tag
#define		HIVE_CONTEXT_TAG					'HCxC'							//缓冲Tag
#define		HIVE_RESOURCE_TAG					'HRxC'							//缓冲Tag

//交互程序定义错误
#define		STATUS_User_Not_Login				((NTSTATUS)0xE0003301L)			//用户未登录
#define		STATUS_Create_Access_Lack			((NTSTATUS)0xE0003302L)			//没有Create权限
#define		STATUS_Write_Access_Lack			((NTSTATUS)0xE0003303L)			//没有Write权限
#define		STATUS_Read_Access_Lack				((NTSTATUS)0xE0003304L)			//没有Read权限
#define		STATUS_Rename_Access_Lack			((NTSTATUS)0xE0003305L)			//没有Rename权限
#define		STATUS_Delete_Access_Lack			((NTSTATUS)0xE0003306L)			//没有Delete权限
#define		STATUS_Delete_Directory_Lack		((NTSTATUS)0xE0003307L)			//没有删除文件夹的权限
#define		STATUS_Rename_Directory_Lack		((NTSTATUS)0xE0003308L)			//没有重命名文件夹的权限
#define		STATUS_Is_Directory_Failed			((NTSTATUS)0xE0003309L)			//判断是否文件夹时失败
#define		STATUS_Much_File_Number				((NTSTATUS)0xE000330AL)			//当前打开文件个数过多
#define		STATUS_Server_Exception				((NTSTATUS)0xE000330BL)			//接口访问异常
#define		STATUS_Unknown_Interface			((NTSTATUS)0xE000330CL)			//未知的接口调用
#define		STATUS_Query_Process_Failed			((NTSTATUS)0xE000330DL)			//查询进程名失败

//Hive服务器定义错误
#define		STATUS_Internal_Error				((NTSTATUS)0xE0000001L)			//系统内部错误																1
#define		STATUS_Invalid_Pool 				((NTSTATUS)0xE0000065L)			//POOL无效(仅验证是否存在该POOL,不验证用户与POOL的关系)						101
#define		STATUS_Pool_Access_Lack				((NTSTATUS)0xE0000066L)			//POOL的所有UNIT不可用(空间已满或禁用的UNIT)								102
#define		STATUS_Invalid_FilePath				((NTSTATUS)0xE0000067L)			//文件路径无效																103
#define		STATUS_Invalid_FileSize				((NTSTATUS)0xE0000069L)			//文件大小无效																105
#define		STATUS_UnitBuffer_Lack				((NTSTATUS)0xE000006AL)			//Unit空间已满，写入失败													106
#define		STATUS_File_Not_Exist				((NTSTATUS)0xE000006BL)			//物理文件不存在															107
#define		STATUS_No_File_Record				((NTSTATUS)0xE000006CL)			//根据文件路径未查询到文件记录												108
#define		STATUS_File_Status_Error			((NTSTATUS)0xE000006DL)			//文件状态错误																109
#define		STATUS_File_Already_Exist			((NTSTATUS)0xE000006EL)			//文件已存在																110
#define		STATUS_Record_Not_Exist				((NTSTATUS)0xE000006FL)			//文件记录不存在															111
#define		STATUS_Analyze_File_Failed			((NTSTATUS)0xE000007DL)			//解析文件路径失败															125
#define		STATUS_Get_FileSzie_Failed			((NTSTATUS)0xE000007EL)			//获取文件大小失败:[创建SSHUtil失败]										126
#define		STATUS_Unknown_Record				((NTSTATUS)0xE000012DL)			//删除文件失败,未查询到文件记录												301
#define		STATUS_Delete_File_Failed			((NTSTATUS)0xE0000132L)			//删除物理文件失败															306
#define		STATUS_File_In_Use					((NTSTATUS)0xE0000135L)			//删除文件失败,文件已使用													309
#define		STATUS_Delete_Record_Failed			((NTSTATUS)0xE0000137L)			//删除文件失败,删除FileRecord记录失败										311
#define		STATUS_Access_Lack					((NTSTATUS)0xE0002714L)			//没有权限访问																10001
#define		STATUS_System_Error					((NTSTATUS)0xE0002715L)			//拒绝访问,系统尚未注册或传入的系统名称有误									10002
#define		STATUS_UserToken_Is_Null			((NTSTATUS)0xE0002714L)			//拒绝访问,User Token不能为空												10003
#define		STATUS_Invalid_UserToken			((NTSTATUS)0xE0002715L)			//拒绝访问,User Token无效													10004
#define		STATUS_Invalide_Signature			((NTSTATUS)0xE0002714L)			//拒绝访问,系统认证签名无效													10005
#define		STATUS_System_Forbidden				((NTSTATUS)0xE0002715L)			//拒绝访问,当前系统已被禁用													10006
#define		STATUS_No_User_Info					((NTSTATUS)0xE0002714L)			//请求中未获取到用户信息													10007
#define		STATUS_SiteID_Error					((NTSTATUS)0xE0002715L)			//拒绝访问，站点尚未注册或传入的站点名称有误								10008
#define		STATUS_UserToken_Overdue			((NTSTATUS)0xE0002714L)			//拒绝访问，User Token已过期，已被清除										10009
#define		STATUS_Differ_SiteID				((NTSTATUS)0xE0002715L)			//拒绝访问，当前请求站点与认证时站点不符									10010
#define		STATUS_Unsupport_Interface			((NTSTATUS)0xE0002714L)			//拒绝访问,请求接口不支持系统签名认证										10011

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

//定义Unit信息
typedef struct _UNIT_INFORMATION
{
	wchar_t		chFilePath[MAX_PATH];
	wchar_t		chUserName[MAX_PATH];
	wchar_t		chPassword[MAX_PATH];

}UNIT_INFORMATION, *PUNIT_INFORMATION;

//定义Process信息
typedef struct _PROC_INFORMATION
{
	wchar_t		chProcess[MAX_PATH];

}PROC_INFORMATION, *PPROC_INFORMATION;

//定义Process信息
typedef struct _FILTER_DISKINFO
{
	wchar_t		chNetDisk[MAX_PATH];

}FILTER_DISKINFO, *PFILTER_DISKINFO;