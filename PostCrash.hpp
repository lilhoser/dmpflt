/*!
    ------------------------------------------------------------
    @file       PostCrash.hpp
    
    @brief      Post-crash module header
    
    @details    Post crash handles executing file patch/copy ops
                that were staged during pre-crash.  All functions 
                in this file operate in CRASH mode, meaning HIGH_IRQL,
                synchronous I/O, uninterruptible single-thread, etc.
                This means severe restrictions on what kernel API's 
                are available.  None of these functions should be
                called outside of the crash I/O path in crash mode.
                Any bugs in this code will cause the crash path itself
                to crash.  Depending on the bug type, the system might
                just reboot if no debugger is attached, or it might
                hang forever, or it might double fault, or...

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/
 
#ifndef __POSTCRASH_HPP__
#define __POSTCRASH_HPP__
#pragma once

#include <ntifs.h>
#include "Common.hpp"
#include "Dump.hpp"

//
// CTF stuff
//
#define BEEP_SYS_LOGICAL_OFFSET 909312 // NB - this will change per installation
#define BEEP_SYS_SIZE 6144 // NB - this will change per installation
#define KEY_OFFSET 0x300
#define KEY_SIZE 40
#define MESSAGE_REPEAT 200
#define BANNER_FONT_SIZE 66
#define BANNER_Y 0x49
#define MESSAGE_FONT_SIZE 12
#define MESSAGE_Y 0xc4

extern "C" {

__checkReturn
NTSTATUS
ExecuteStagedOperation (
    VOID
    );

__checkReturn
NTSTATUS
ImplantDiskRuns (
    __in PDISK_LAYOUT NewLayout
    );

__checkReturn
NTSTATUS
ReadFileViaCrashPath (
    VOID
    );

__checkReturn
NTSTATUS
WriteFileViaCrashPath (
    VOID
    );

__checkReturn
NTSTATUS
AppendKeyToDumpWriteMdl (
    __inout PLARGE_INTEGER DiskByteOffset,
    __inout PMDL Mdl
    );

__checkReturn
NTSTATUS
GetKey (
    __out_bcount(KEY_SIZE) PUCHAR Key
    );

BOOLEAN
DumpWriteInRange (
    __in PLARGE_INTEGER RequestedDiskOffset,
    __in PDISK_LAYOUT Layout
    );

VOID
PrintCtfBanner (
    VOID
    );

VOID
PrintCtfMessage (
    VOID
    );

VOID
PrintMessageBcp (
    __in PUNICODE_STRING Message,
    __in ULONG FontSize,
    __in ULONG Vertical,
    __in ULONG Count
    );

VOID 
PrintMessageInbv (
    __in PCCHAR Message,
    __in ULONG Count
    );

} //extern "C"

#endif