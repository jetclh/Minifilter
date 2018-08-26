/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

pch.h

Abstract:

This module includes all  the headers which need to be
precompiled & are included by all the source files in this
project


Environment:

Kernel mode


--*/

#ifndef __CTX_PCH_H__
#define __CTX_PCH_H__

//
//  Enabled warnings
//

// #pragma warning(error:4100)     //  Enable-Unreferenced formal parameter
// #pragma warning(error:4101)     //  Enable-Unreferenced local variable
// #pragma warning(error:4061)     //  Eenable-missing enumeration in switch statement
// #pragma warning(error:4505)     //  Enable-identify dead functions
//#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  Includes
//

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "Ntstrsafe.h"
#include "HiveMiniProc.h"

#endif __CTX_PCH_H__

QUERY_INFO_PROCESS	ZwQueryInformationProcess;
FILTER_DATA			gFilterData;
