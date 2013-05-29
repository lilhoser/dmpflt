/*!
    ------------------------------------------------------------
    @file       Dump.hpp
    
    @brief      Header file containing structure definitions,       
                static globals, and other defines specific to
                crashdmp.sys
    
    @author     Aaron LeMasters
    ------------------------------------------------------------
*/

#ifndef __DUMP_HPP__
#define __DUMP_HPP__
#pragma once

#include "Common.hpp"

//
// All offsets/magic/etc below are only valid on Win8 RTM x86
//

//
// Offsets of magic bytes that identify crashdmp.sys internal
// functions we need to call
//
#define WRITELOGDATATODISK_MAGIC 0x01cc878b
#define WRITELOGDATATODISK_DISTANCE 58
#define READLOGDATAFROMDISK_MAGIC 0x6a9c458d
#define READLOGDATAFROMDISK_DISTANCE 35
#define CLEARLOGFILE_MAGIC 0x01acb73b 
#define CLEARLOGFILE_DISTANCE 74

//
// Offsets to fields in crashdmp context structure
// we need to be able to read/modify
//
#define LOGFILE_HANDLE_OFFSET 0x1d4
#define LOGFILE_DISK_RUNS_OFFSET 0x1b4

//
// Offsets of magic bytes for ntoskrnl functions to
// write to dump screen
//
#define NTOS_BCPDISPLAYCHAR_MAGIC 0xfff6b5e8
#define NTOS_BCPDISPLAYCHAR_DISTANCE 98
#define NTOS_BGPCLEAR_MAGIC 0x001fc0ba
#define NTOS_BGPCLEAR_DISTANCE 88
#define NTOS_BCPDISPLAYSTR_MAGIC 0x0538c06b
#define NTOS_BCPDISPLAYSTR_DISTANCE 14
#define NTOS_BCPSETCURSORPOSITION_MAGIC 0x0ff875f7
#define NTOS_BCPSETCURSORPOSITION_DISTANCE 133

//
// CTF related messages
//
static const PWCHAR g_DumpStackLogName = L"\\??\\C:\\DumpStack.log.tmp";
const PWCHAR g_Banner = L"*<|:-)";

static ULONG g_BugCheckCode = 0x00C0FFEE;
static ULONG g_BugCheckParam1 = 0x00C0FFEE;
static ULONG g_BugCheckParam2 = 0x00C0FFEE;
static ULONG g_BugCheckParam3 = 0x00C0FFEE;
static ULONG g_BugCheckParam4 = 0x00C0FFEE;

//
// Crashdmp.sys internal function prototypes
//
typedef 
NTSTATUS
(__thiscall *
ReadLogDataFromDisk) (
    __in PVOID Context, // should go in ECX b/c we use thiscall, but compiler
                        // optimizations definitely break this!
    __inout PVOID Buffer,
    __in ULONG RunNumber,
    __in ULONG BytesToRead,
    __in LARGE_INTEGER DiskRunByteOffset
    );

typedef
NTSTATUS
(__stdcall *
WriteLogDataToDisk) (
    //first param passed in <edi>
    __in PVOID Buffer,
    __in CHAR Update
    );

typedef 
NTSTATUS
(NTAPI *
ClearLogFile) (
    __in PVOID Context
    );

//
// Ntoskrnl.exe internal function prototypes
//
typedef 
NTSTATUS
(__stdcall *
BgpClearScreen) (
    ULONG RgbColor
    );

typedef 
NTSTATUS
(__stdcall *
BgpConsoleDisplayString) (
    PWCHAR String
    );

typedef 
NTSTATUS
(__stdcall *
BcpDisplayCriticalString) (
    __in PUNICODE_STRING String,
    __in ULONG FontSize,
    __in ULONG Unknown //always seems to be zero    
    );

typedef 
NTSTATUS
(__stdcall *
BcpDisplayCriticalCharacter) (
    __in CHAR Character,
    __in ULONG FontSize
    );

typedef 
NTSTATUS
(__stdcall *
BcpSetCursorPosition) (
    __in ULONG X,
    __in ULONG Y,
    __in ULONG Unknown //always seems to be zero    
    );

//
// Exported kernel display functions
//

typedef
VOID
(NTAPI*
InbvAcquireDisplayOwnership)(
    VOID
);

typedef
BOOLEAN
(NTAPI*
InbvDisplayString)(
    __in PCCH String
);

typedef
BOOLEAN
(NTAPI*
InbvEnableDisplayString)(
    __in BOOLEAN Enable
);

typedef
BOOLEAN
(NTAPI*
InbvResetDisplay)(
    VOID
);

typedef
VOID
(NTAPI*
InbvSetScrollRegion)(
    __in ULONG Left,
    __in ULONG Top,
    __in ULONG Width,
    __in ULONG Height
);

typedef
VOID
(NTAPI*
InbvSetTextColor)(
    __in ULONG Color
);

typedef
VOID
(NTAPI*
InbvSolidColorFill)(
    __in ULONG Left,
    __in ULONG Top,
    __in ULONG Width,
    __in ULONG Height,
    __in ULONG Color
);


//
// From FSCTL_QUERY_RETRIEVAL_POINTERS msdn doc.
//
typedef struct _MAPPING_PAIR
{
    ULONGLONG SectorSize;
    ULONGLONG LogicalOffset;
} MAPPING_PAIR, *PMAPPING_PAIR;

//
// Contains all of the disk runs retrieved from a query
// to FSCTL_QUERY_RETRIEVAL_POINTERS that describe a file.
//
typedef struct _DISK_LAYOUT
{
    ULONG NumDiskRuns;
    PMAPPING_PAIR DiskRuns;
} DISK_LAYOUT, *PDISK_LAYOUT;

//
// Undocumented FILTER_CONTEXT structure accessible
// to all crash dump filter drivers by "walking up"
// from the parameters they receive in DriverEntry
//
typedef struct _FILTER_CONTEXT
{
    //
    // Address of this field is passed to our DriverEntry
    // as the second argument (RegistryPath)
    //
    FILTER_INITIALIZATION_DATA FilterInitData;
    //
    // Address of this field is passed to our DriverEntry
    // as the first argument (DriverObject)
    //
    FILTER_EXTENSION FilterExtension;
    //
    // We are in a doubly-linked list of filter drivers
    //
    LIST_ENTRY Link;
    //
    // An unknown ULONG, possibly flag or mask
    //
    ULONG UnknownNumber;
    //
    // A pointer to crashdmp.sys's global context structure,
    // which we SHOULDN'T have access to, but it's available.
    //
    PVOID Context;
    //
    // Unknown pointer - maybe something to do with
    // driver image or something else
    //
    PVOID UnknownPointer;
} FILTER_CONTEXT, *PFILTER_CONTEXT;

#endif
