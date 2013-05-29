/*!
    ------------------------------------------------------------
    @file       DmpFlt.hpp
    
    @brief      DmpFlt module header
    
    @details    The DmpFlt module contains DriverEntry and other
                core functions for crash dump filter callbacks.

    @author     Aaron LeMasters
    ------------------------------------------------------------
 */

#ifndef __DMPFLT_HPP__
#define __DMPFLT_HPP__
#pragma once

#include "Helper.hpp"
#include <ntdddisk.h>
#include <ntdddump.h>
#include "Common.hpp"
#include "Timer.hpp"
#include "Dump.hpp"
#include "PostCrash.hpp"

extern "C" {

CALLBACK_FUNCTION Initialize;
DRIVER_INITIALIZE DriverEntry;
DUMP_START FltDumpStart;
DUMP_FINISH FltDumpFinish;
DUMP_UNLOAD FltDumpUnload;
DUMP_WRITE FltDumpWrite;
DUMP_READ FltDumpRead;

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );
VOID
Initialize (
    __in_opt PVOID CallbackContext,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2
    );

VOID
Cleanup (
    VOID
    );

__checkReturn
NTSTATUS
InitializeContext (
    VOID
    );

BOOLEAN
GetKernelFunction (
    __in PWCHAR Name,
    __out PULONG_PTR Address
    );

NTSTATUS
FltDumpStart (
    __in PFILTER_EXTENSION FilterExtension
    );
    
NTSTATUS
FltDumpFinish (
    __in PFILTER_EXTENSION FilterExtension
    );

NTSTATUS
FltDumpUnload (
    __in PFILTER_EXTENSION FilterExtension
    );

NTSTATUS
FltDumpWrite (
    __in PFILTER_EXTENSION FilterExtension,
    __inout PLARGE_INTEGER DiskByteOffset,
    __inout PMDL Mdl
    );

NTSTATUS
FltDumpRead (
    __in PFILTER_EXTENSION FilterExtension,
    __in PLARGE_INTEGER DiskByteOffset,
    __in PMDL Mdl
    );

VOID
PrintFilters (
    VOID
    );

}

#endif