/*!
    ------------------------------------------------------------
    @file       Helper.cpp
    
    @brief      Helper library implementation
    
    @details    The Helper module contains functions for enumerating
                loaded modules, scanning for function signatures in
                an image section, and other misc things.

    @author     Aaron LeMasters
    ------------------------------------------------------------
 */

#include "Helper.hpp"

extern "C"
{

/*!

    @brief Attempts to locate the named driver using AuxKlib

    @param[in] DriverName - Name of driver to find

    @param[out] ImageBase - The base address of the located driver image
                or 0 if not found.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
FindDriverByName (
    __in PCHAR DriverName,
    __out PULONG_PTR ImageBase
    )
{
    NTSTATUS status;
    PAUX_MODULE_EXTENDED_INFO moduleInfo, currentModule;
    ULONG size;
    PCHAR driverName;
    ULONG_PTR end, name;
    ANSI_STRING a, b;

    NT_ASSERT(DriverName != NULL);
    NT_ASSERT(ImageBase != NULL);

    *ImageBase = 0;
    moduleInfo = NULL;
    size = 0;

    status = AuxKlibInitialize();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not initialize AuxKlib: %08x\n", status);
        goto Exit;
    }

    status = AuxKlibQueryModuleInformation(&size,
                                           sizeof(AUX_MODULE_EXTENDED_INFO),
                                           NULL);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: AuxKlib query failed: %08x\n", status);
        goto Exit;
    }

    NT_ASSERT(size != 0);

    //
    // Allocate some memory for the module list
    //
    moduleInfo = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(NonPagedPool,
                                                                  size,
                                                                  DMPFLT_TAG);
    if (moduleInfo == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DBGPRINT("DmpFlt: Could not allocate module list of size %lu.\n", size);
        goto Exit;
    }

    //
    // And now query it. We should check status and handle failure.
    //
    AuxKlibQueryModuleInformation(&size,
                                  sizeof(AUX_MODULE_EXTENDED_INFO),
                                  moduleInfo);

    //
    // Scan all the modules
    //
    driverName = NULL;
    end = (ULONG_PTR)moduleInfo + size;
    RtlInitAnsiString(&a, DriverName);

    for (currentModule = moduleInfo; (ULONG_PTR)currentModule < end; currentModule++)
    {
        name = (ULONG_PTR)currentModule->FullPathName + currentModule->FileNameOffset;

        if (name < end)
        {
            RtlInitAnsiString(&b, (PCHAR)name);

            if (RtlEqualString(&a, &b, TRUE))
            {
                *ImageBase = (ULONG_PTR)currentModule->BasicInfo.ImageBase;
                status = STATUS_SUCCESS;
                goto Exit;
            }
        }
    }

    status = STATUS_NOT_FOUND;

Exit:

    if (moduleInfo != NULL)
    {
        ExFreePoolWithTag(moduleInfo, DMPFLT_TAG);
    }

    return status;

}

/*!

    @brief Scans an image text section for a function signature.

    @details Attempts to locate the address of the supplied 'magic' bytes within the 
             given section by name.  The distance value is added to the discovered
             location, which should return the address of the function.  This is a 
             really lame technique and is only suitable for play.  A single
             byte change from recompilation will break this!!!!

    @param[in] SectionName - Name of the section to search

    @param[in] SectionNameLength - The size of the section

    @param[in] DriverBase - The base address of the driver containing the section

    @param[in] Magic - Function signature (DWORD only) to scan for

    @param[in] Distance - The offset to add back to the returned match address

    @param[out] Address - The address of the requested function.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
ScanDriverSection (
    __in PCHAR SectionName,
    __in USHORT SectionNameLength,
    __in DWORD_PTR DriverBase, 
    __in ULONG Magic,
    __in ULONG Distance,
    __out PULONG_PTR Address
    )
{
    DWORD_PTR sectionAddress;
    ULONG sectionSize;
    ULONG offset; 
    NTSTATUS status;

    NT_ASSERT(DriverBase != 0);
    NT_ASSERT(Address != NULL);

    *Address = 0;
    offset = 0;

    //
    // Locate the section by name
    //
    status = GetSectionAddress(DriverBase,
                               SectionName,
                               SectionNameLength,
                               &sectionSize,
                               &sectionAddress);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate a section named %s: %08x\n", 
                 SectionName,
                 status);
        goto Exit;
    }

    //
    // Scan section for magic bytes.
    //
    while ((offset + 4) < sectionSize)
    {
        if ( (*((PULONG)(sectionAddress + offset))) == Magic)
        {
            *Address = (DWORD_PTR)(sectionAddress + offset - Distance);
            status = STATUS_SUCCESS;
            goto Exit;
        }

        offset++;
    }

    status = STATUS_NOT_FOUND;

Exit:

    return status;
}


/*!

    @brief Locates the address of the name section in the supplied image

    @param[in] BaseAddress - The address of the image in memory

    @param[in] Text - The name of the section to find

    @param[in] TextLength - The size of the name in bytes

    @param[out] SectionSize - The size of the matching section

    @param[out] Address - The address of the matching section

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
GetSectionAddress (
    __in DWORD_PTR BaseAddress,
    __in PCHAR Text,
    __in USHORT TextLength,
    __out PULONG SectionSize,
    __out PULONG_PTR Address
    )
{
    ULONG tableSize;
    ULONG firstSection;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    DWORD_PTR start,curr,sectionCount;
    SIZE_T compare;
    NTSTATUS status;

    NT_ASSERT(BaseAddress != NULL);
    NT_ASSERT(SectionSize != NULL);
    NT_ASSERT(Address != NULL);
    NT_ASSERT(Text != NULL);
    NT_ASSERT(TextLength > 0);

    *Address = 0;
    *SectionSize = 0;
    compare = 0;

    ntHeader = RtlImageNtHeader((PVOID)BaseAddress);

    if (ntHeader == NULL)
    {
        DBGPRINT("DmpFlt: Failed to get nt header for image at %p.\n", 
                (PVOID)BaseAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    if (ntHeader->FileHeader.NumberOfSections == 0)
    {
        DBGPRINT("DmpFlt: Image at %p has no sections!\n", 
                (PVOID)BaseAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    tableSize = sizeof(IMAGE_SECTION_HEADER) * ntHeader->FileHeader.NumberOfSections;
    firstSection = dosHeader->e_lfanew + sizeof(ULONG) + 
                   sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader;
    start = BaseAddress + firstSection;
    curr = start;
    sectionCount = 0;

    while (sectionCount < ntHeader->FileHeader.NumberOfSections)
    {
        compare = RtlCompareMemory(((PIMAGE_SECTION_HEADER)curr)->Name, Text, TextLength);

        if (compare == 5)
        {
            *SectionSize = ((PIMAGE_SECTION_HEADER)curr)->Misc.VirtualSize;
            *Address = BaseAddress + ((PIMAGE_SECTION_HEADER)curr)->VirtualAddress;
            status = STATUS_SUCCESS;
            goto Exit;
        }

        curr += sizeof(IMAGE_SECTION_HEADER);
        sectionCount++; 
    }

    DBGPRINT("DmpFlt: Unable to find a section named '%s'.\n", Text);
    status = STATUS_NOT_FOUND;

Exit:

    return status;
}


/*!

    @brief Determines if the platform is 64-bit or not and optionally
           whether the given process is 32-bit (wow'd) or not.

    @details If no eprocess is specified, the function returns TRUE if the architecture
             is 64-bit and FALSE if the architecture is 32-bit.  If an eprocess is 
             specified, the function returns TRUE only if both the architecture AND the 
             given process is 64-bit.  Otherwise, returns FALSE. This function uses the 
             presence or absence of the IoIs32bitProcess to determine if the architecture 
             supports 64-bit.

    @param[inopt] Process - Pointer to an EPROCESS to attach to

    @param[out] Is64Bit - TRUE if the platform (and optional EPROCESS) is 64-bit

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
Is64bitProcess (
    __in_opt PRKPROCESS Process,
    __out PBOOLEAN Is64Bit
    )
{
    UNICODE_STRING function;
    lpfnIoIs32bitProcess functionPointer;
    KAPC_STATE apc;
    NTSTATUS status;

    NT_ASSERT(Is64Bit != NULL);

    RtlInitUnicodeString(&function,L"IoIs32bitProcess");

    //
    // If the routine IoIs32bitProcess doesn't exist, 
    // we are gauranteed to be on a 32-bit platform.
    //
#pragma warning(disable:4055)
    functionPointer = (lpfnIoIs32bitProcess)MmGetSystemRoutineAddress(&function);

    if (functionPointer == NULL)
    {
        *Is64Bit = FALSE;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    //
    // if no eprocess was passed in, we just want to know 
    // if we are 64-bit ARCHITECTURE.
    //
    if (Process == NULL)
    {
        *Is64Bit = TRUE;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    status = STATUS_SUCCESS;
    *Is64Bit = TRUE;

    //
    // Attach to target process context to determine if it is truly 64-bit
    // or just wow64.
    //
    KeStackAttachProcess(Process, &apc);

    if (functionPointer(NULL))
    {
        *Is64Bit = FALSE;
    }

    KeUnstackDetachProcess(&apc);

Exit:

    return status;
}

} // extern "C"