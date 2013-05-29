/*!
    ------------------------------------------------------------
    @file       PreCrashStaging.hpp
    
    @brief      PreCrashStaging module header
    
    @details    Pre crash staging handles all aspects of manipulating
                crashdmp.sys that must occur before the system enters
                crash/hiber mode.

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/
#ifndef __PRECRASHSTAGING_HPP__
#define __PRECRASHSTAGING_HPP__
#pragma once

#include <ntifs.h>
#include "Common.hpp"
#include "Dump.hpp"

//
// Globals and constants only useful to pre-crash staging ops.
//
#define MAX_PATH 512
#define MAX_REQUESTED_FILENAME_SIZE (MAX_PATH * sizeof(CHAR))
#define MINIMUM_FILE_SIZE 4096
#define MAXIMUM_FILE_SIZE 1048576 //1mb
#define MAX_PATCH_PARAMETER_SIZE (MAX_REQUESTED_FILENAME_SIZE + 1024)

//
// Used only by DisableDriver() to rename our driver
//
const PCHAR g_FilterDriverPath = "\\??\\C:\\Windows\\System32\\Drivers\\storport_lsi.sys";
const PWCHAR g_FilterRename = L"Via100d2.sys";
             
typedef enum _OPEN_TYPE
{
    OpenTypeDumpStackLog = 1,
    OpenTypePatchOrCopy = 2,
    OpenTypeDriverRename = 3
} OPEN_TYPE;

extern "C" {

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
ExposeDumpStackLogFile (
    VOID
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
StageFilePatch (
    VOID
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
StageFileCopy (
    VOID
    );

__drv_maxIRQL(PASSIVE_LEVEL)
BOOLEAN
IsValidFile (
    __in PCHAR FileName
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
OpenFileViaNormalPath (
    __in PCHAR Name,
    __in OPEN_TYPE OpenType,
    __out PHANDLE Handle,
    __out PFILE_OBJECT* FileObject,
    __out PULONGLONG Size
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
GetFileDiskRuns (
    __in HANDLE Handle,
    __in PLARGE_INTEGER Size,
    __out PDISK_LAYOUT Layout
    );

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
ParsePatchParameters (
    __in PUCHAR Parameters,
    __in ULONG ParameterSize,
    __inout PREQUESTED_FILE_ATTRIBUTES RequestedFile,
    __out PCHAR* TargetFileName
    );

__checkReturn
NTSTATUS
SaveDumpStackLogDiskRuns (
    VOID
    );

__checkReturn
NTSTATUS
DisableDriver (
    VOID
    );

#ifdef DBG
__checkReturn
NTSTATUS
GetBeepSysInformation (
    VOID
    );
#endif

} //extern "C"

#endif