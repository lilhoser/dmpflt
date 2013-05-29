/*!
    ------------------------------------------------------------
    @file       Common.hpp
    
    @brief      Header file containing structure definitions,       
                static globals, and other defines common to all
                modules in this project.
    
    @author     Aaron LeMasters
    ------------------------------------------------------------
*/

#ifndef __COMMON_HPP__
#define __COMMON_HPP__
#pragma once

#include <ntdddisk.h>
#include <ntdddump.h>
#include "Dump.hpp"

#define LODWORD(ll) ((ULONG)(ll))
#define HIDWORD(ll) ((ULONG)(((ULONGLONG)(ll) >> 32) & 0xFFFFFFFF))
#define LOWORD(l) ((USHORT)(l))
#define HIWORD(l) ((USHORT)(((ULONG)(l) >> 16) & 0xFFFF))
#define LOBYTE(w) ((UCHAR)(w))
#define HIBYTE(w) ((UCHAR)(((USHORT)(w) >> 8) & 0xFF))
#define MAKEQWORD(l,h) ((((ULONGLONG)h) << 32) |  \
                            (((ULONGLONG)l) & 0xFFFFFFFF))


#ifdef DBG
#define DBGPRINT(Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, Format, __VA_ARGS__);
#else
#define DBGPRINT(Format, ...)
#endif

#define DMPFLT_TAG 'xxaA'

//
// Dont move this!
//
#define MAX_PATCH_BYTE_COUNT 64

//
// Structure definitions
//
typedef enum _KNOWN_OS
{
    Win2k = 0xa,
    WinXPSp23 = 0xb,
    Win2k3sp2 = 0xc,
    WinVista_Sp2 = 0xd,
    Win7_2008R2_sp1 = 0xe,
    Win8 = 0xf,
    MaxOs
} KNOWN_OS;

typedef struct _IPI_CALL_ARGUMENT
{
    volatile LONG Barrier;
    PVOID Context;
    PKIPI_BROADCAST_WORKER Callback;
} IPI_CALL_ARGUMENT, *PIPI_CALL_ARGUMENT;

typedef enum _CHALLENGE_STAGE
{
    ChallengeBegin = 0,
    ChallengeStage1 = 1,
    ChallengeStage2 = 2,
    ChallengeStage3 = 3
} CHALLENGE_STAGE;

typedef enum _STAGED_OPERATION
{
    OperationNone,
    OperationPatch,
    OperationCopy
} STAGED_OPERATION;

typedef struct _REQUESTED_FILE_ATTRIBUTES
{
    DISK_LAYOUT Layout;
    ULONGLONG Size;
    ULONGLONG UsedSize; // if file is too small or too large
    UCHAR OverwriteBytes[MAX_PATCH_BYTE_COUNT];
    ULONG OverwriteLength;
    ULONG OverwriteOffset;
} REQUESTED_FILE_ATTRIBUTES, *PREQUESTED_FILE_ATTRIBUTES;

typedef struct _HOST_INFO
{
    KNOWN_OS OperatingSystem;
    BOOLEAN Is64Bit;
} HOST_INFO, *PHOST_INFO;

typedef struct _DMP_TIMER_INFO
{
    PVOID WorkerThread;
    KTIMER TimerExposeLogFile;
    KTIMER TimerStageFile;
    KTIMER TimerBsod;
    KEVENT StopTimer;
    BOOLEAN TimerSet;
} DMP_TIMER_INFO, *PDMP_TIMER_INFO;

typedef struct _CRASHDMP_INFO
{
    ULONG_PTR CrashdmpReadLogDataFromDisk;
    ULONG_PTR CrashdmpWriteLogDataToDisk;
    ULONG_PTR CrashdmpClearLogFile;
} CRASHDMP_INFO, *PCRASHDMP_INFO;

typedef struct _STAGING_INFO
{
    BOOLEAN LogFileExposed;
    DISK_LAYOUT OriginalFileLayout;
    REQUESTED_FILE_ATTRIBUTES RequestedFileAttributes;
    STAGED_OPERATION StagedOperation;
} STAGING_INFO, *PSTAGING_INFO;

typedef struct _CTF_STATE_INFO
{
    UCHAR CtfStageCompleted;
    BOOLEAN KeyFileRequested;
    PMDL KeyMdl;    //scratch MDL used in DumpWrite callback to dump CTF key
    BOOLEAN KeyDumped;
} CTF_STATE_INFO, *PCTF_STATE_INFO;

typedef struct _KERNEL_INFO
{
    ULONG_PTR BcpDisplayCriticalCharacter;
    ULONG_PTR BcpDisplayCriticalString;
    ULONG_PTR BcpSetCursorPosition;
    ULONG_PTR BgpClearScreen;
    ULONG_PTR BgpConsoleDisplayString;
    ULONG_PTR InbvAcquireDisplayOwnership;
    ULONG_PTR InbvDisplayString;
    ULONG_PTR InbvResetDisplay;
    ULONG_PTR InbvSetScrollRegion;
    ULONG_PTR InbvEnableDisplayString;
    ULONG_PTR InbvSolidColorFill;
    ULONG_PTR InbvSetTextColor;
} KERNEL_INFO, *PKERNEL_INFO;

typedef struct _DMPFLT_CONTEXT
{
    PFILTER_EXTENSION Extension;
    PFILTER_INITIALIZATION_DATA InitializationData;
    PUCHAR Buffer;
    ULONG BufferSize;
    BOOLEAN DriverDisabled;
    DMP_TIMER_INFO TimerInformation;
    HOST_INFO HostInformation;
    CRASHDMP_INFO CrashdmpInformation;
    STAGING_INFO StagingInformation;
    CTF_STATE_INFO CtfStateInformation;
    KERNEL_INFO KernelInformation;
} DMPFLT_CONTEXT, *PDMPFLT_CONTEXT;

#endif