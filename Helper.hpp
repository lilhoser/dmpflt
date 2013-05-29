/*!
    ------------------------------------------------------------
    @file       Helper.hpp
    
    @brief      Helper library header
    
    @details    The Helper module contains functions for enumerating
                loaded modules, scanning for function signatures in
                an image section, and other misc things.

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/
 
#ifndef __HELPER_HPP__
#define __HELPER_HPP__
#pragma once

#include <ntifs.h>
#include <Aux_klib.h>
#include <ntimage.h>
#include "Common.hpp"

extern "C"
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader (
    __in PVOID Base
    );

typedef BOOLEAN (*lpfnIoIs32bitProcess)(IN PIRP Irp OPTIONAL);

extern "C" {

__checkReturn
NTSTATUS
FindDriverByName (
    __in PCHAR DriverName,
    __out PULONG_PTR ImageBase
    );

__checkReturn
NTSTATUS
#pragma prefast(warning: 6504, "Fourth parameter IS a pointer!")
GetSectionAddress (
    __in DWORD_PTR BaseAddress,
    __in PCHAR Text,
    __in USHORT TextLength,
    __out PULONG SectionSize,
    __out PULONG_PTR Address
    );

__checkReturn
NTSTATUS
ScanDriverSection (
    __in PCHAR SectionName,
    __in USHORT SectionNameLength,
    __in DWORD_PTR DriverBase, 
    __in ULONG Magic,
    __in ULONG Distance,
    __out PULONG_PTR Address
    );

__checkReturn
NTSTATUS
Is64bitProcess (
    __in_opt PRKPROCESS Process,
    __out PBOOLEAN Is64Bit
    );

}  //extern "C"

#endif