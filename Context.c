/*++

Copyright (c) 2016 - 2019  Sobey Corporation

Module Name:

	context.c

Abstract:

	This is the stream file context module of the kernel mode context sample filter driver.

Environment:

	Kernel mode

--*/


#include "Include.h"


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FindOrCreateFileContext)
#pragma alloc_text(PAGE, CreateFileContext)
#pragma alloc_text(PAGE, UpdateNameInFileContext)
#endif


NTSTATUS
FindOrCreateFileContext(
	_In_ PFLT_CALLBACK_DATA Data,
	_In_ BOOLEAN CreateIfNotFound,
	_When_(CreateIfNotFound != FALSE, _In_) _When_(CreateIfNotFound == FALSE, _In_opt_) PUNICODE_STRING FileName,
	_Outptr_ PFILE_CONTEXT *FileContext,
	_Out_opt_ PBOOLEAN ContextCreated
)
/*++

Routine Description:

This routine finds the file context for the target file.
Optionally, if the context does not exist this routing creates
a new one and attaches the context to the file.

Arguments:

Data                  - Supplies a pointer to the callbackData which declares the requested operation.
CreateIfNotFound      - Supplies if the file context must be created if missing
FileName              - Supplies the file name
FileContext           - Returns the file context
ContextCreated        - Returns if a new context was created

Return Value:

Status

--*/
{
	NTSTATUS status;
	PFILE_CONTEXT pFileContext		= NULL;
	PFILE_CONTEXT pOldFileContext	= NULL;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CreateIfNotFound);
	UNREFERENCED_PARAMETER(FileName);
	UNREFERENCED_PARAMETER(FileContext);
	UNREFERENCED_PARAMETER(ContextCreated);

	*FileContext = NULL;
	if (ContextCreated != NULL) *ContextCreated = FALSE;

	//
	//  First try to get the file context.
	//
	status = FltGetFileContext(Data->Iopb->TargetInstance,
		Data->Iopb->TargetFileObject,
		&pFileContext);

	//
	//  If the call failed because the context does not exist
	//  and the user wants to creat a new one, the create a
	//  new context
	//
	if (!NT_SUCCESS(status) && (status == STATUS_NOT_FOUND) && CreateIfNotFound) {

		//
		//  Create a file context
		//
		status = CreateFileContext(FileName, &pFileContext);

		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Failed to create file context, status(0x%08x), FileObject(0x%08x), Instance(0x%08x)\n", \
					status, Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance));

			return status;
		}
		//
		//  Set the new context we just allocated on the file object
		//
		status = FltSetFileContext(Data->Iopb->TargetInstance,
			Data->Iopb->TargetFileObject,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			pFileContext,
			&pOldFileContext);

		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("[HiveMiniFilter]: Failed to set file context, status(0x%08x), FileObject(0x%08x), Instance(0x%08x)\n", \
					status, Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance));
			//
			//  We release the context here because FltSetFileContext failed
			//
			//  If FltSetFileContext succeeded then the context will be returned
			//  to the caller. The caller will use the context and then release it
			//  when he is done with the context.
			//
			FltReleaseContext(pFileContext);

			if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

				//
				//  FltSetFileContext failed for a reason other than the context already
				//  existing on the file. So the object now does not have any context set
				//  on it. So we return failure to the caller.
				//

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("[HiveMiniFilter]: Failed to set file context, status(0x%08x), FileObject(0x%08x), Instance(0x%08x)\n", \
						status, Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance));

				return status;
			}

			//
			//  Race condition. Someone has set a context after we queried it.
			//  Use the already set context instead
			//

			//
			//  Return the existing context. Note that the new context that we allocated has already been
			//  realeased above.
			//

			pFileContext = pOldFileContext;
			status = STATUS_SUCCESS;
		}
		else 
		{
			if (ContextCreated != NULL)
			{
				*ContextCreated = TRUE;
			}
		}
	}
	*FileContext = pFileContext;

	return status;
}


NTSTATUS
CreateFileContext(
	_In_ PUNICODE_STRING FileName,
	_Outptr_ PFILE_CONTEXT *FileContext
)
/*++

Routine Description:

This routine creates a new file context

Arguments:

FileName            - Supplies the file name
FileContext         - Returns the file context

Return Value:

Status

--*/
{
	NTSTATUS status;
	PFILE_CONTEXT pFileContext = NULL;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(FileName);
	UNREFERENCED_PARAMETER(FileContext);

	//
	//  Allocate a file context
	//
	status = FltAllocateContext(gFilterData.Filter,
		FLT_FILE_CONTEXT,
		FILE_CONTEXT_SIZE,
		PagedPool,
		&pFileContext);

	if (!NT_SUCCESS(status)) {

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("[HiveMiniFilter]: Failed to allocate file context, status(0x%08x)\n", status));
		return status;
	}
	//
	//  Initialize the newly created context
	//
	RtlZeroMemory(pFileContext, FILE_CONTEXT_SIZE);
	status = HiveAllocateUnicodeString(&pFileContext->FileName, HIVE_CONTEXT_TAG);
	if (NT_SUCCESS(status)) {

		//
		//  Allocate and copy off the file name
		//
		RtlCopyUnicodeString(&pFileContext->FileName, FileName);
	}
	//
	//  Initialize the resource of context
	//
	pFileContext->Resource = HiveAllocateResource();
	if (pFileContext->Resource == NULL) {

		FltReleaseContext(pFileContext);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ExInitializeResourceLite(pFileContext->Resource);

	*FileContext = pFileContext;

	return STATUS_SUCCESS;
}

NTSTATUS
UpdateNameInFileContext(
	_In_ PUNICODE_STRING DirectoryName,
	_Inout_ PFILE_CONTEXT FileContext
)
/*++

Routine Description:

This routine updates the name of the target in the supplied stream context

Arguments:

DirectoryName       - Supplies the directory name
StreamContext		- Returns the updated name in the stream context

Return Value:

Status

Note:

The caller must synchronize access to the context. This routine does no
synchronization

--*/
{
	NTSTATUS status;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(DirectoryName);
	UNREFERENCED_PARAMETER(FileContext);

	//
	//  Free any existing name
	//
	if (FileContext->FileName.Buffer != NULL) {

		HiveFreeUnicodeString(&FileContext->FileName, HIVE_CONTEXT_TAG);
	}
	//
	//  Allocate and copy off the directory name
	//
	status = HiveAllocateUnicodeString(&FileContext->FileName, HIVE_CONTEXT_TAG);
	if (NT_SUCCESS(status)) {

		RtlCopyUnicodeString(&FileContext->FileName, DirectoryName);
	}
	return status;
}
