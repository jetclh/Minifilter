/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

	operations.c

Abstract:

	This is the support routines for clean up parameters.

Environment:

	Kernel mode

--*/


#include "Include.h"


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CleanUpAllowPath)
#pragma alloc_text(PAGE, CleanUpAllowProcess)
#pragma alloc_text(PAGE, CleanUpFilterNetDisk)
#pragma alloc_text(PAGE, CleanUpFileInfo)
#endif


//
//  Support Routines
//

VOID CleanUpAllowPath()
{
	ULONG ulIndex = 0;

	for (ulIndex = 0; ulIndex < gFilterData.stAllowData.ulAllowedpath; ulIndex++)
	{
		HiveFreeUnicodeString(&gFilterData.stAllowData.arrAllowedPath[ulIndex], HIVE_STRING_TAG);
		HiveFreeUnicodeString(&gFilterData.stAllowData.arrUserName[ulIndex], HIVE_STRING_TAG);
		HiveFreeUnicodeString(&gFilterData.stAllowData.arrPassword[ulIndex], HIVE_STRING_TAG);
	}
	RtlZeroMemory(&gFilterData.stAllowData, sizeof(ALLOW_PATH));
}

VOID CleanUpAllowProcess()
{
	ULONG ulIndex = 0;

	for (ulIndex = 0; ulIndex < gFilterData.stAllowProcess.ulAllowedProcess; ulIndex++)
	{
		HiveFreeUnicodeString(&gFilterData.stAllowProcess.arrAllowedProcess[ulIndex], HIVE_STRING_TAG);
	}
	RtlZeroMemory(&gFilterData.stAllowProcess, sizeof(ALLOW_PROCESS));
}

VOID CleanUpFilterNetDisk()
{
	ULONG ulIndex = 0;

	for (ulIndex = 0; ulIndex < gFilterData.stNetDisk.ulNetDisk; ulIndex++)
	{
		HiveFreeUnicodeString(&gFilterData.stNetDisk.arrNetDisk[ulIndex], HIVE_STRING_TAG);
	}
	RtlZeroMemory(&gFilterData.stNetDisk, sizeof(FILTER_NETDISK));
}

VOID
CleanUpFileInfo(PUNICODE_STRING pString)
{
	ULONG ulIndex = 0;

	if (pString != NULL)
	{//清除指定文件信息
		for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
		{
			if (gFilterData.stFileInfo.ulOperateType[ulIndex] != 0 &&
				RtlEqualUnicodeString(pString, &gFilterData.stFileInfo.arrFilePath[ulIndex], TRUE))
			{
				gFilterData.stFileInfo.ulOperateType[ulIndex]	= 0;
				gFilterData.stFileInfo.ulFileSize[ulIndex]		= 0;
				gFilterData.stFileInfo.status[ulIndex]			= STATUS_SUCCESS;
				HiveFreeUnicodeString(&gFilterData.stFileInfo.arrFilePath[ulIndex], HIVE_STRING_TAG);
				break;
			}
		}
	}
	else
	{//清除全部文件信息
		for (ulIndex = 0; ulIndex < MAX_FILE_NUMBER; ulIndex++)
		{
			if (gFilterData.stFileInfo.ulOperateType[ulIndex] != 0)
			{
				HiveFreeUnicodeString(&gFilterData.stFileInfo.arrFilePath[ulIndex], HIVE_STRING_TAG);
			}
		}
		RtlZeroMemory(&gFilterData.stFileInfo, sizeof(FILTER_FILE_INFO));
	}
}