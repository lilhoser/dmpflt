/*!
    ------------------------------------------------------------
    @file       PreCrashStaging.cpp
    
    @brief      PreCrashStaging module implementation
    
    @details    Pre crash staging handles all aspects of manipulating
                crashdmp.sys that must occur before the system enters
                crash/hiber mode.  All functions in this file can
                safely use all kernel API's and assume PASSIVE_LEVEL.

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/

#include "PreCrashStaging.hpp"

extern "C" {

//
// Pointer to our global context structure
//
extern PDMPFLT_CONTEXT g_Context;

/*!

    @brief This function "exposes" the crash dump stack logging file
        at c:\dumpstack.log.tmp to user mode by closing the handle
        and reopening it with share access and less-restrictive ACL.
        This function is called periodically via a timer.   Once it
        successfully exposes the dump stack log file, it is not called
        again.

    @details This function manipulates the handle to the dump stack logging file
        which crashdmp.sys leaves hanging around in its internal context
        structure which we have access to in our DriverEntry.  Note that 
        crashdmp.sys NEVER uses this handle when actually logging information
        to this log file - it is opened for exclusive access and set as a hidden,
        system file.

    @return NTSTATUS code

*/
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
ExposeDumpStackLogFile (
    VOID
    )
{
    NTSTATUS status;
    PHANDLE handle;
    PFILTER_CONTEXT context;
    SECURITY_DESCRIPTOR descriptor;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    IO_STATUS_BLOCK ioStatusBlock;

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 
    handle = (PHANDLE)((ULONG_PTR)context->Context + LOGFILE_HANDLE_OFFSET);

    DBGPRINT("DmpFlt: Exposing dump stack log...\n");

    //
    // Close the handle that crashdmp.sys created so we can 
    // open in shared mode.
    //
    // NB: This handle will be garbage/zero if dump stack logging hasn't been enabled
    // in the registry yet.  In that case, ZwClose will fail, and we will know
    // not to attempt any log actions.
    //
    status = ZwClose(*handle);

    if (!NT_SUCCESS(status))
    {
#pragma prefast(suppress: 6273, "Value being passed is not a pointer!")
        DBGPRINT("DmpFlt: Could not close existing log handle %08x:  %08x\n", 
                 *handle,
                 status);
        goto Exit;
    }

    //
    // Now re-open the log file in share mode so user mode can access it.
    // These settings were chosen to conform as closely as possible to
    // what crashdmp.sys already uses.
    //
    RtlInitUnicodeString(&name, g_DumpStackLogName);
    InitializeObjectAttributes(&attributes, 
                               &name, 
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    status = ZwOpenFile(handle, 
                        (GENERIC_READ | GENERIC_WRITE),
                        &attributes, 
                        &ioStatusBlock, 
                        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
                        (FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH | 
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_COMPRESSION));

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not open dump stack log: %08x\n", status);
        goto Exit;
    }

    //
    // Store the new handle back in context structure so the crash dump stack
    // can use it on next crash/hibernate.
    //
    *(PULONG)((ULONG_PTR)context->Context + LOGFILE_HANDLE_OFFSET) = (ULONG)*handle;

    //
    // Create an empty descriptor with no restrictions.
    //
    status = RtlCreateSecurityDescriptor(&descriptor, 1);

    if (!NT_SUCCESS(status))
    {
#pragma prefast(suppress: 6273, "Value being passed is not a pointer!")
        DBGPRINT("DmpFlt: Could not create security descriptor for handle %08x:  %08x\n", 
                 *handle,
                 status);
        goto Exit;
    }

    //  
    // Set the DACL on the log file to have no restrictions
    //
    status = ZwSetSecurityObject(*handle,
                                 DACL_SECURITY_INFORMATION,
                                 &descriptor);

    if (!NT_SUCCESS(status))
    {
#pragma prefast(suppress: 6273, "Value being passed is not a pointer!")
        DBGPRINT("DmpFlt: Could not set security descriptor for handle %08x:  %08x\n", 
                 *handle,
                 status);
        goto Exit;
    }

    DBGPRINT("DmpFlt: Successfully exposed dump stack log file.\n");

    status = STATUS_SUCCESS;
    g_Context->StagingInformation.LogFileExposed = TRUE;

Exit:

    //
    // NB: We do NOT close the log handle.  We are mimicking what crashdmp.sys does
    // when it first created this file - leave the handle open so it's available
    // at crash time.
    //

    return status;
}

/*!

    @brief This function attempts to "stage" a file patch operation to be completed
        by the post-crash staging module at crash/hiber time.  It is called
        periodically via a timer.

    @details  This function simply reads the contents of the C:\Dumpstack.log.tmp 
        file using the normal I/O path and attempts to parse the following information:
            {file_to_patch}|{patch_offset}|{patch_bytes}

        If the parse is successful, the file's disk runs are queried through
        the normal I/O path and stored in our context structure for use at crash time.  
        Note that the dump stack log file's disk runs, which we overwrite at post
        crash time, are saved now, so that we don't have to attempt to retrieve
        them at crash time, when the normal I/O path is unavailable.
        Note that if a patch operation is successfully staged, it will override 
        any read staging.

    @return NTSTATUS code

*/
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
StageFilePatch (
    VOID
    )
{
    NTSTATUS status;
    LARGE_INTEGER size;
    PHANDLE logHandle;
    PREQUESTED_FILE_ATTRIBUTES requestedFile;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER offset;
    PCHAR targetFileName;
    ULONG parameterSize;
    PFILTER_CONTEXT context;
    HANDLE handle;
    PFILE_OBJECT fileObject;

    requestedFile = NULL;
    offset.QuadPart = 0;
    targetFileName = NULL;
    parameterSize = 0;
    handle = NULL;
    fileObject = NULL;

    if (g_Context->StagingInformation.LogFileExposed == FALSE)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    DBGPRINT("DmpFlt: Attempting to stage a file patch...\n");

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 
    logHandle = (PHANDLE)((ULONG_PTR)context->Context + LOGFILE_HANDLE_OFFSET);
    requestedFile = &g_Context->StagingInformation.RequestedFileAttributes;

    RtlZeroMemory(g_Context->Buffer, MAX_PATCH_PARAMETER_SIZE);

    //
    // Attempt to read patch parameters
    // Do NOT wait on I/O using the logHandle, since this handle
    // was opened with FILE_SYNCHRONOUS_IO_NONALERT  flag set.
    //
    status = ZwReadFile(*logHandle,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatusBlock,
                        g_Context->Buffer,
                        MAX_PATCH_PARAMETER_SIZE,
                        &offset,
                        NULL);   

    NT_ASSERT(status != STATUS_PENDING);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to read %i bytes from dump stack log: %08x\n", 
                 MAX_PATCH_PARAMETER_SIZE,
                 status);
        goto Exit;
    }

    parameterSize = ioStatusBlock.Information;

    //
    // Attempt to parse parameter string and if successful,
    // these parameters will be applied at crash time to
    // patch the requested file.
    //
    status = ParsePatchParameters(g_Context->Buffer,
                                  parameterSize,
                                  requestedFile,
                                  &targetFileName);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to parse patch parameters: %08x\n", status);
        goto Exit;
    }

    //
    // Attempt to open the requested file
    //
    status = OpenFileViaNormalPath(targetFileName, 
                                   OpenTypePatchOrCopy,
                                   &handle, 
                                   &fileObject,
                                   &requestedFile->Size);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to open target file: %08x\n", status);
        goto Exit;
    }

    DBGPRINT("DmpFlt: Successfully opened target file.\n");

    //
    // Validate the patch parameters
    //
    if (requestedFile->Size < (requestedFile->OverwriteOffset + 
                                requestedFile->OverwriteLength))
    {
        DBGPRINT("DmpFlt: Requested patch offset and length not valid for file of size %I64u\n", 
                 requestedFile->Size);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    size.QuadPart = requestedFile->Size;

    //
    // Attempt to locate the disk runs for the file.
    //
    status = GetFileDiskRuns(handle, &size, &requestedFile->Layout);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to get disk runs for target file: %08x\n", status);
        goto Exit;
    }

    //
    // Save the dump stack log file's disk runs currently stored in the common context,
    // so that we don't have to do this at post-crash time.
    //
    status = SaveDumpStackLogDiskRuns();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt:  Failed to save current disk runs for dump log file!\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    DBGPRINT("DmpFlt: Successfully staged target file:\n");
    DBGPRINT("DmpFlt: \tName: %s\n", targetFileName);
    DBGPRINT("DmpFlt: \tSize: %I64u\n", requestedFile->Size);
    DBGPRINT("DmpFlt: \tUsed Size: %I64u\n", size.QuadPart);
    DBGPRINT("DmpFlt: \tDisk run #0 of %lu:\n",
             requestedFile->Layout.NumDiskRuns);
    DBGPRINT("DmpFlt: \t\tSector size: %I64u\n", 
             requestedFile->Layout.DiskRuns[0].SectorSize);
    DBGPRINT("DmpFlt: \t\tLogical offset: %I64u\n", 
             requestedFile->Layout.DiskRuns[0].LogicalOffset);

    //  
    // Setting this prevents any further staging.
    //
    g_Context->StagingInformation.StagedOperation = OperationPatch;

Exit:

    if (handle != NULL)
    {
        status = ZwClose(handle);
    }

    if (fileObject != NULL)
    {
        ObDereferenceObject(fileObject);
    }

    //
    // Reset to known-good state
    //
    if (!NT_SUCCESS(status))
    {
        g_Context->StagingInformation.StagedOperation = OperationNone;

        if (requestedFile != NULL)
        {
            if (requestedFile->Layout.DiskRuns != NULL)
            {
                ExFreePool(requestedFile->Layout.DiskRuns);
            }

            RtlZeroMemory(requestedFile, sizeof(REQUESTED_FILE_ATTRIBUTES));
        }
    }
    
    return status;
}


/*!

    @brief This function attempts to "stage" a file copy operation to be completed
        by the post-crash staging module at crash/hiber time.

    @details  This function is called periodically via a timer.  It simply
        reads the contents of the C:\Dumpstack.log.tmp file using the normal 
        I/O path and attempts to parse a path to a target file.  If the parse
        is successful, the file's disk runs are queried through the normal I/O
        path and stored in our context structure for use at crash time.  Note
        that the dump stack log file's disk runs, which we overwrite at post
        crash time, are saved now, so that we don't have to attempt to retrieve
        them at crash time, when the normal I/O path is unavailable.

    @return NTSTATUS code

*/
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
StageFileCopy (
    VOID
    )
{
    PFILTER_CONTEXT context;
    NTSTATUS status;
    LARGE_INTEGER size;
    PHANDLE logHandle;
    HANDLE handle;
    PREQUESTED_FILE_ATTRIBUTES requestedFile;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER offset;
    PFILE_OBJECT fileObject;

    handle = NULL;
    requestedFile = NULL;
    offset.QuadPart = 0;
    fileObject = NULL;

    //
    // Staging a file copy operation for the purposes of the CTF
    // challenge require that we have exposed the DumpStack.log.tmp
    // to user mode.
    //
    if (g_Context->StagingInformation.LogFileExposed == FALSE)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    DBGPRINT("DmpFlt: Attempting to stage a file copy operation...\n");

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 
    logHandle = (PHANDLE)((ULONG_PTR)context->Context + LOGFILE_HANDLE_OFFSET);
    requestedFile = &g_Context->StagingInformation.RequestedFileAttributes;

    RtlZeroMemory(g_Context->Buffer, MAX_REQUESTED_FILENAME_SIZE);

    //
    // Attempt to read a file name 
    // Do NOT wait on I/O using the logHandle, since this handle
    // was opened with FILE_SYNCHRONOUS_IO_NONALERT  flag set.
    //
    status = ZwReadFile(*logHandle,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatusBlock,
                        g_Context->Buffer,
                        MAX_REQUESTED_FILENAME_SIZE,
                        &offset,
                        NULL);   

    NT_ASSERT(status != STATUS_PENDING);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to read from dump stack log: %08x\n", status);
        goto Exit;
    }

    g_Context->Buffer[MAX_REQUESTED_FILENAME_SIZE / sizeof(CHAR)] = ANSI_NULL;

    //
    // Attempt to open the requested file
    //
    status = OpenFileViaNormalPath((PCHAR)g_Context->Buffer, 
                                   OpenTypePatchOrCopy,
                                   &handle,
                                   &fileObject,
                                   &requestedFile->Size);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to open requested file: %08x\n", status);
        goto Exit;
    }

    //
    // Make sure the file is allowed
    //
    if (IsValidFile((PCHAR)g_Context->Buffer) == FALSE)
    {
        status = STATUS_INVALID_PARAMETER;
        DBGPRINT("DmpFlt: Invalid file name specified!");
        goto Exit;
    }

    DBGPRINT("DmpFlt: Successfully opened requested file\n");

    size.QuadPart = requestedFile->Size;

    //
    // Attempt to locate the disk runs for the file and create
    // a mapping based on the calculated size we need.
    //
    status = GetFileDiskRuns(handle, &size, &requestedFile->Layout);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to get disk runs for requested file: %08x\n", 
                 status);
        goto Exit;
    }

    //
    // Save the dump stack log file's disk runs
    // currently stored in the common context,
    // so that we don't have to do this at post-crash time.
    //
    status = SaveDumpStackLogDiskRuns();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt:  Failed to save current disk runs for dump log file!\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // We are limited to how small a file can be transferred using the 
    // dump stack via the logging path.  The ReadLogDataFromDisk() function
    // requires that 4096 bytes were read, at a minimum.  If the user requests
    // a size smaller than that, we will simply read 4096 bytes around it.
    //
    if (requestedFile->Size < MINIMUM_FILE_SIZE)
    {
        requestedFile->UsedSize = MINIMUM_FILE_SIZE;
    }
    else if (requestedFile->Size > MAXIMUM_FILE_SIZE)
    {
        requestedFile->UsedSize = MAXIMUM_FILE_SIZE;
    }
    else
    {
        requestedFile->UsedSize = requestedFile->Size;
    }

    DBGPRINT("DmpFlt: Successfully staged requested file for copy:\n");
    DBGPRINT("DmpFlt: \tName: %s\n", (PCSZ)g_Context->Buffer);
    DBGPRINT("DmpFlt: \tSize: %I64u\n", requestedFile->Size);
    DBGPRINT("DmpFlt: \tUsed Size: %I64u\n", requestedFile->UsedSize);
    DBGPRINT("DmpFlt: \tDisk run #0 of %lu:\n",
             requestedFile->Layout.NumDiskRuns);
    DBGPRINT("DmpFlt: \t\tSector size: %I64u\n", 
             requestedFile->Layout.DiskRuns[0].SectorSize);
    DBGPRINT("DmpFlt: \t\tLogical offset: %I64u\n", 
             requestedFile->Layout.DiskRuns[0].LogicalOffset);

    g_Context->StagingInformation.StagedOperation = OperationCopy;

Exit:

    if (handle != NULL)
    {
        ZwClose(handle);
    }

    if (fileObject != NULL)
    {
        ObDereferenceObject(fileObject);
    }

    //
    // Reset to known-good state
    //
    if (!NT_SUCCESS(status))
    {
        g_Context->StagingInformation.StagedOperation = OperationNone;

        if (requestedFile != NULL)
        {

            if (requestedFile->Layout.DiskRuns != NULL)
            {
                ExFreePool(requestedFile->Layout.DiskRuns);
            }

            RtlZeroMemory(requestedFile, sizeof(REQUESTED_FILE_ATTRIBUTES));
        }
    }

    return status;
}

/*!

    @brief This function determines if a requested file stage/patch operation
        is valid based on the file name.  We also use this opportunity, since
        we're comparing filenames, to flip a flag in our global context structure
        if the user requested key.txt (which impacts CTF).

    @details  Think of this as a "blacklist" of files that are known to cause
        problems if manipulated through the crash I/O path.  The reasons
        that these files are invalid are not fully understood.

    @param[in] FileName - The full path to the requested file in question.

    @return TRUE if the file is valid, FALSE if not

*/
__drv_maxIRQL(PASSIVE_LEVEL)
BOOLEAN
IsValidFile (
    __in PCHAR FileName
    )
{
    PCHAR lastSlash;
    PCHAR fileName;

    lastSlash = strrchr(FileName, '\\');

    if (lastSlash == NULL)
    {
        return FALSE;
    }

    fileName = lastSlash + 1;

    if ((strcmp(fileName, "dumpstack.log.tmp") == 0) ||
        (strcmp(fileName, "hiberfil.sys") == 0) ||
        (strcmp(fileName, "pagefile.sys") == 0) ||
        (strcmp(fileName, "swapfile.sys") == 0) ||
        (strcmp(fileName, "config.sys") == 0))
    {
        DBGPRINT("DmpFlt: Not allowing invalid file %s\n", fileName);
        return FALSE;
    }
    
    //
    // If key.txt was supplied, remember this for bugcheck time
    //
    if (strcmp(fileName, "key.txt") == 0) 
    {
        g_Context->CtfStateInformation.KeyFileRequested = TRUE;
    }

    return TRUE;
}


/*!

    @brief Attempts to retrieve the disk runs for the requested file, 
           via the normal I/O path (file system driver).

    @details  There are numerous caveats with this function, please
        read the comments in the function body.

    @param[in] Handle - A handle to the file whose runs are to be retrieved.
        See the comments below, as this handle must be opened in a special way.
        Also see comments in OpenFileViaNormalPath().

    @param[in] Size - The size of the target file.

    @param[out] Layout - If successful, contains the disk runs for the target file.

    @return NTSTATUS code

*/
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
GetFileDiskRuns (
    __in HANDLE Handle,                     // must be opened in special way
    __in PLARGE_INTEGER Size,               // must be the file size
    __out PDISK_LAYOUT Layout
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    PMAPPING_PAIR pair;
    PMAPPING_PAIR pair2;
    ULONGLONG totalSize;

    pair = NULL;

    //
    // This is a limitation in the paging I/O path I don't
    // really grok, but sure enough, a small file bugchecks
    // the fuck out of everything.. must be larger than
    // sector size
    //
    if (Size->QuadPart < 512)
    {
        DBGPRINT("DmpFlt: File is too small for paging I/O\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Locate the sectors and offsets on disk where this file resides.
    //
    // Note that we are using FSCTL_QUERY instead of FSCTL_GET, which 
    // is technically a bug, bc we can't guarantee that the file is not
    // mirrored on multiple volumes.  We should really use FSCTL_GET here
    // and reconstruct the VCN->LCN mapping, but in the interest of PoC
    // code and replicating how the crash dump stack does it (the crash
    // dump stack can rely on 1:1 mapping from VCN->LCN since it operates
    // on boot device only), we won't bother.
    //
    // NB: MSDN docs are wrong again.  We dont allocate the output buffer,
    // it's allocated for us and we must free it.
    //
    // NB: The handle must have been opened with special access using
    // IoCreateFile.  See OpenFileViaNormalPath() for details.
    //
    status = ZwFsControlFile(Handle,
                             NULL,
                             NULL,
                             NULL,
                             &ioStatusBlock,
                             FSCTL_QUERY_RETRIEVAL_POINTERS,
                             Size,
                             sizeof(LARGE_INTEGER),
                             (PVOID)&pair,
                             sizeof(PVOID));

    NT_ASSERT(status != STATUS_PENDING);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not obtain disk run mapping pairs: %08x\n", 
                 status);
        goto Exit;
    }

    NT_ASSERT(pair != NULL);

    //
    // There should be at least one entry with a non-zero sector size.
    //
    if (pair->SectorSize == 0)
    {
        DBGPRINT("DmpFlt: Invalid file format - no disk runs returned.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }    

    pair2 = pair;
    Layout->NumDiskRuns = 0;
    totalSize = 0;

    while (pair2->SectorSize != 0)
    {
        totalSize += pair2->SectorSize;

        //
        // If we've reached the max file size we want to transfer,
        // zero out the next run in the list, which will signal
        // the consumer to stop.
        //
        if (totalSize > MAXIMUM_FILE_SIZE)
        {
            pair2->SectorSize = 0;
            pair2->LogicalOffset = 0;
            break;
        }

        Layout->NumDiskRuns++;
        pair2++;
    }

    //
    // If there are 0 runs here, we broke out of the loop before we got
    // passed the first disk run.  This means the first run had 
    // too much data, so we can't use this file.
    //
    if (Layout->NumDiskRuns == 0)
    {
        DBGPRINT("DmpFlt: Requested file is too large and in a single run.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Free any previous allocation
    // NB: It's os-allocated, so dont use our tag.
    //
    if (Layout->DiskRuns != NULL)
    {
        ExFreePool(Layout->DiskRuns);
    }

    Layout->DiskRuns = pair;

    //
    // We are limited to how small a file can be transferred using the 
    // dump stack via the logging path.  The ReadLogDataFromDisk() function
    // requires that 4096 bytes were read, at a minimum.  If the user requests
    // a size smaller than that, we will simply read 4096 bytes around it.
    //
    if (Size->QuadPart < MINIMUM_FILE_SIZE)
    {
        //      
        // Not sure on this - but if the file is this small, it shouldn't
        // be in multiple runs, you'd think...
        //
        NT_ASSERT(Layout->NumDiskRuns == 1);

        Layout->DiskRuns[0].SectorSize = MINIMUM_FILE_SIZE;
    }

    status = STATUS_SUCCESS;

Exit:
    
    return status;
}


/*!

    @brief Attempts to open the requested file via the normal I/O path.  

    @details  There are numerous caveats with this function, please
        read the comments in the function body and this header. The caller
        is responsible for releasing the handle upon successful result.  The handle 
        is NOT waitable - all I/O issued through the handle returned by this function 
        is ALWAYS waited on by I/o Mgr.  All I/O sent through the handle returned
        by this function is through the page file!  This carries a lot of
        implications and we should actually restructure all of this to not require
        this - it would mean NOT using FSCTL_QUERY_RETREIVAL_POINTERS later.

    @param[in] Name - The full path to the file
    
    @param[in] OpenType - Indicates the intent of the open operation.

    @param[out] Handle - A handle to the file on success; caller must close.  The caller
        CANNOT wait on this handle, since this function always tells the I/O mgr to wait
        on the I/O for completion.

    @param[out] Size - The size of the target file.

    @return NTSTATUS code

*/
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
OpenFileViaNormalPath (
    __in PCHAR Name,
    __in OPEN_TYPE OpenType,
    __out PHANDLE Handle,
    __out PFILE_OBJECT* FileObject,
    __out PULONGLONG Size
    )
{
    UNICODE_STRING name;
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_STANDARD_INFORMATION information;
    ANSI_STRING string;
    ULONG objectFlags;
    ULONG shareAccess, openOptions, accessMask;
    BOOLEAN kernelHandle;

    *Size = 0;
    name.Buffer = NULL;
    kernelHandle = TRUE;

    if (Name[0] != '\\')
    {
        DBGPRINT("DmpFlt: Invalid file name format.\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    
    RtlInitAnsiString(&string, Name);

    status = RtlAnsiStringToUnicodeString(&name, &string, TRUE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not convert ANSI name string: %08x\n", status);
        goto Exit;
    }

    //
    // The access mask is different based on the type of file we are opening.
    // However, ALL access mask values include SYNCHRONIZE flag.
    //
    switch (OpenType)
    {
        //
        // DumpStack.log.tmp handle   
        // We need to let user mode access it and change its DACL
        //
        case OpenTypeDumpStackLog:
        {
            accessMask = FILE_GENERIC_READ;
            kernelHandle = FALSE;
            break;
        }
        //
        // We are copying or patching some file on disk through the crash path
        // and thus we need this handle to retrieve it's disk runs. This requires
        // a special open type.
        //
        case OpenTypePatchOrCopy:
        {
            accessMask = (SYNCHRONIZE | WRITE_DAC | FILE_READ_DATA | FILE_WRITE_DATA | DELETE);
            break;
        }
        //
        // We are renaming our current driver to disable it, standard arguments.
        //
        case OpenTypeDriverRename:
        {
            accessMask = GENERIC_READ | GENERIC_WRITE;
            break;
        }
        default:
        {
            NT_ASSERT(FALSE);
            status = STATUS_INVALID_PARAMETER;
            DBGPRINT("DmpFlt: Invalid OpenType request %lu\n", OpenType);
            goto Exit;
        }
    }


    //
    // Open the requested file.
    // 
    objectFlags = OBJ_CASE_INSENSITIVE;
    objectFlags |= (kernelHandle != FALSE) ? OBJ_KERNEL_HANDLE : 0;
    InitializeObjectAttributes(&attributes, 
                               &name, 
                               objectFlags,
                               NULL,
                               NULL);
    openOptions = (FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH |
                   FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_COMPRESSION);
    shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    //
    // A note on SL_OPEN_PAGING_FILE:
    //
    // This flag (which is set in crashdmp.sys when it opens a handle
    // to the dump stack log file along with IO_NO_PARAMETER_CHECKING), 
    // causes a flag to be set in the IRP that indicates the I/O is
    // through the paging file.  Ntfs!NtfsQueryRetrievalPointers, which
    // we call indirectly when we attempt to locate retrieval pointers,
    // requires this flag to be set.  Otherwise we would have to use
    // FSCTL_GET_RETRIEVAL_POINTERS, which we really should be doing...
    // Greetz to Alex Ionescu.
    //

    status = IoCreateFile(Handle,
                          accessMask,
                          &attributes,
                          &ioStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          shareAccess,
                          FILE_OPEN,
                          openOptions,
                          NULL,
                          NULL,
                          CreateFileTypeNone,
                          NULL,
                          (SL_OPEN_PAGING_FILE | IO_NO_PARAMETER_CHECKING));

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not open requested file: %08x\n", status);
        goto Exit;
    }

    //
    // Grab FILE_OBJECT so we can wait on the handle
    //
    status = ObReferenceObjectByHandle(*Handle, 
                                       0,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID*)FileObject,
                                       NULL);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not obtain reference to requested file: %08x\n", status);
        goto Exit;
    }

    //
    // Get file size
    //
    status = ZwQueryInformationFile(*Handle,
                                    &ioStatusBlock,
                                    &information,
                                    sizeof(information),
                                    FileStandardInformation);

    NT_ASSERT(status != STATUS_PENDING);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not get file size for requested file: %08x\n", 
                 status);
        goto Exit;
    }

    *Size = information.EndOfFile.QuadPart;

Exit:

    if (name.Buffer != NULL)
    {
        RtlFreeUnicodeString(&name);
    }

    return status;
}


/*!

    @brief Attempts to extract parameters for a patch operation from the 
        specified string.

    @param[in] Parameters - The string to parse

    @param[in] ParameterSize - Length of the string in bytes

    @param[inout] RequestedFile - Pointer to a REQUESTED_FILE_ATTRIBUTES structure that
        stores the resulting patch arguments for post-crash time.

    @param[out] TargetFileName - The parsed file name

    @return NTSTATUS code

*/
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
ParsePatchParameters (
    __in PUCHAR Parameters,
    __in ULONG ParameterSize,
    __inout PREQUESTED_FILE_ATTRIBUTES RequestedFile,
    __out PCHAR* TargetFileName
    )
{
    NTSTATUS status;
    PCHAR location;
    PWCHAR location2;
    ULONG count;
    PCHAR pathEnd;
    PCHAR offsetEnd;
    ULONG pathSize;
    ULONG offsetSize;
    ULONG patchBytesSize;
    ANSI_STRING string;
    UNICODE_STRING string2;
    UNICODE_STRING string3;
    ULONG i;
    ULONG number;

    string2.Buffer = NULL;
    *TargetFileName = NULL;
    count = 0;

    //
    // Very basic sanity check that should prevent
    // a large class of stupid malformed format tricks.
    //
    if (ParameterSize < 10)
    {
        DBGPRINT("DmpFlt: Invalid patch format!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    location = strchr((const char*)Parameters, '|');

    while (location != NULL)
    {
        count++;
        location++;
        location = strchr(location, '|');
    }

    if (count != 2)
    {
        DBGPRINT("DmpFlt: Invalid patch format!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Parse path
    //
    pathEnd = strchr((const char*)Parameters, '|');

    if (pathEnd == NULL)
    {
        DBGPRINT("DmpFlt: Path specified in patch format is invalid!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    pathSize = ((ULONG_PTR)pathEnd - (ULONG_PTR)Parameters);

    if (pathSize < 4 || pathSize > MAX_REQUESTED_FILENAME_SIZE)
    {
        DBGPRINT("DmpFlt: Path specified in patch format is invalid!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Null-terminate the path before assigning it.
    //
    *pathEnd = ANSI_NULL;
    *TargetFileName = (PCHAR)Parameters;

    //
    // Parse offset
    //
    offsetEnd = strchr(pathEnd + 1, '|');

    if (offsetEnd == NULL)
    {
        DBGPRINT("DmpFlt: Offset specified in patch format is invalid!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    offsetSize = ((ULONG_PTR)offsetEnd - (ULONG_PTR)pathEnd + 1);

    if (offsetSize < 1) //this does not validate the offset is valid
    {
        DBGPRINT("DmpFlt: Offset specified in patch format is too small!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Force null-term the offset string, so that string init function
    // will terminate it correctly before converting.
    //
    *offsetEnd = ANSI_NULL;

    RtlInitAnsiString(&string, pathEnd + 1);

    status = RtlAnsiStringToUnicodeString(&string2, &string, TRUE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to convert ansi to unicode string: %08x\n", status);
        goto Exit;  
    }

    status = RtlUnicodeStringToInteger(&string2, 0, &RequestedFile->OverwriteOffset);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to convert offset to a number: %08x\n", status);
        goto Exit;  
    }

    RtlFreeUnicodeString(&string2);
    string2.Buffer = NULL;

    //
    // Parse patch bytes and size
    //
    patchBytesSize = (((ULONG_PTR)Parameters + ParameterSize) - 
                      ((ULONG_PTR)offsetEnd + 1));

    if (patchBytesSize < 1) //this does not validate the patch size is valid
    {
        DBGPRINT("DmpFlt: Patch size specified in patch format is too small!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Count how many comma-separated bytes there are
    //
    count = 0;
    location = strchr((const char*)offsetEnd + 1, ',');

    while (location != NULL)
    {
        count++;
        location++;
        location = strchr(location, ',');
    }
    
    if (count == 0 || count >= MAX_PATCH_BYTE_COUNT)
    {
        DBGPRINT("DmpFlt: Patch size specified in patch format is invalid!\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RtlInitAnsiString(&string, offsetEnd + 1);

    status = RtlAnsiStringToUnicodeString(&string2, &string, TRUE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to convert ansi to unicode string: %08x\n", status);
        goto Exit;  
    }

    string3.Buffer = string2.Buffer;
    string3.MaximumLength = string2.MaximumLength;
    string3.Length = string2.Length;

    RequestedFile->OverwriteLength = 0;

    for (i = 0; i < count + 1 ; i++)
    {
        //
        // This function considers the first non-numeric character, 
        // in our case the second ",", to be the terminator.
        //
        status = RtlUnicodeStringToInteger(&string3, 0, &number);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("DmpFlt: Failed to convert patch byte to number: %08x\n", status);
            goto Exit;
        }

        if (number == 0)
        {
            DBGPRINT("DmpFlt: Failed to convert patch byte to number\n");
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        RequestedFile->OverwriteBytes[i] = (UCHAR)number;
        RequestedFile->OverwriteLength++;

        location2 = wcschr(string3.Buffer, L',');

        if (location2 == NULL)
        {
            break;
        }

        location2++;

        NT_ASSERT((ULONG_PTR)location2 < ((ULONG_PTR)string3.Buffer + string3.Length));

        //
        // Move the buffer pointer to point to the next number
        //
        string3.Length -= (USHORT)((ULONG_PTR)location2 - (ULONG_PTR)string3.Buffer);
        string3.Buffer = location2;
    }

    DBGPRINT("DmpFlt: Successfully parsed patch parameters:\n");
    DBGPRINT("DmpFlt: \tOffset = 0x%08x\n", RequestedFile->OverwriteOffset);
    DBGPRINT("DmpFlt: \tNum bytes = %i\n", RequestedFile->OverwriteLength);

    status = STATUS_SUCCESS;

Exit:

    if (string2.Buffer != NULL)
    {
        RtlFreeUnicodeString(&string2);
    }

    //
    // Reset to known-clean state
    //
    if (!NT_SUCCESS(status))
    {
        RtlZeroMemory(RequestedFile->OverwriteBytes, MAX_PATCH_BYTE_COUNT);
        RequestedFile->OverwriteLength = 0;
        RequestedFile->OverwriteOffset = 0;
    }

    return status;
}

/*!

    @brief Saves the disk runs for the original dumpstack log file in our
        global context structure so that they're available during post-crash.
           
    @details It is necessary to save them now, since at post-crash time we
        cannot allocate memory.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
SaveDumpStackLogDiskRuns (
    VOID
    )
{
    PFILTER_CONTEXT context;
    PDISK_LAYOUT layout;
    PDISK_LAYOUT oldLayout;
    ULONG size;
    NTSTATUS status;
    ULONG i;

    oldLayout = &g_Context->StagingInformation.OriginalFileLayout;
    context = (PFILTER_CONTEXT)g_Context->InitializationData; 

    NT_ASSERT(context != NULL);
    NT_ASSERT(context->Context != NULL);

    layout = (PDISK_LAYOUT)((ULONG_PTR)context->Context + LOGFILE_DISK_RUNS_OFFSET);

    //
    // Validate the dump stack log disk runs stored
    // in the common context structure
    //
    if (layout == NULL)
    {
        status = STATUS_INVALID_PARAMETER;
        DBGPRINT("DmpFlt: Current dump stack log file has no layout!\n");
        goto Exit;
    }

    if (layout->NumDiskRuns <= 0)
    {
        status = STATUS_INVALID_PARAMETER;
        DBGPRINT("DmpFlt: Current dump stack log file has no runs!\n");
        goto Exit;
    }
    
    //
    // Free any prior allocation we made.
    //
    if (oldLayout->DiskRuns != NULL)
    {
        ExFreePoolWithTag(oldLayout->DiskRuns, DMPFLT_TAG);
    }

    //
    // Allocate num + 1 because last one has to be set to zero
    //
    size = (layout->NumDiskRuns + 1) * sizeof(MAPPING_PAIR);
    oldLayout->DiskRuns = (PMAPPING_PAIR)ExAllocatePoolWithTag(NonPagedPool,
                                                                size,
                                                                DMPFLT_TAG);

    if (oldLayout->DiskRuns == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DBGPRINT("DmpFlt: Failed to allocate a mapping pair\n");
        goto Exit;
    }

    oldLayout->NumDiskRuns = layout->NumDiskRuns;

    for (i = 0; i < layout->NumDiskRuns; i++)
    {
        oldLayout->DiskRuns[i].LogicalOffset = layout->DiskRuns[i].LogicalOffset;
        oldLayout->DiskRuns[i].SectorSize = layout->DiskRuns[i].SectorSize;
    }
    
#pragma prefast(suppress: 6386, "This is not a buffer overrun!")
    oldLayout->DiskRuns[i].LogicalOffset = 0;
    oldLayout->DiskRuns[i].SectorSize = 0;

    status = STATUS_SUCCESS;

Exit:

    return status;
}

/*!

    @brief Disables our own driver by simply renaming it
           
    @details This is used after the final stage of the CTF challenge is finished.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
DisableDriver (
    VOID
    )
{
    NTSTATUS status;
    ULONGLONG size;
    HANDLE handle;
    IO_STATUS_BLOCK ioStatusBlock;
    WCHAR fileName[80];
    FILE_RENAME_INFORMATION rename;
    UNICODE_STRING name;
    PFILE_OBJECT fileObject;

    handle = NULL;
    fileObject = NULL;

    //  
    // Only the first call to this function will succeed
    //
    if (g_Context->DriverDisabled != FALSE)
    {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    RtlInitUnicodeString(&name, g_FilterRename);
    rename.ReplaceIfExists = TRUE;
    rename.RootDirectory = NULL;
    rename.FileNameLength = name.Length;
    RtlCopyMemory(rename.FileName, g_FilterRename, name.Length);
#pragma prefast(suppress: 6386, "Buffer is guaranteed to be large enough")
    fileName[name.Length] = UNICODE_NULL;

    //
    // Attempt to open the requested file
    //
    status = OpenFileViaNormalPath(g_FilterDriverPath, 
                                   OpenTypeDriverRename,
                                   &handle,
                                   &fileObject, 
                                   &size);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to open driver file: %08x\n", status);
        goto Exit;
    }
    
    //
    // Do NOT wait on I/O using the logHandle, since this handle
    // was opened with FILE_SYNCHRONOUS_IO_NONALERT flag set.
    //
    status = ZwSetInformationFile(handle, 
                                  &ioStatusBlock,
                                  &rename,
                                  sizeof(rename) + name.Length,
                                  FileRenameInformation);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to set rename information for driver: %08x\n",
                 status);
        goto Exit;
    }

    DBGPRINT("DmpFlt: Successfully disabled driver.\n");

    g_Context->DriverDisabled = TRUE;
    status = STATUS_SUCCESS;

Exit:

    if (handle != NULL)
    {
        ZwClose(handle);
    }

    if (fileObject != NULL)
    {
        ObDereferenceObject(fileObject);
    }

    return status;
}


/*!

    @brief Retrieves the disk offset and size of beep.sys
           
    @details The CTF challenge stores the key in this file. This is a debug
        function meant for challenge setup only.

    @return NTSTATUS code

*/
#ifdef DBG
__checkReturn
NTSTATUS
GetBeepSysInformation (
    VOID
    )
{
    NTSTATUS status;
    ULONGLONG size;
    HANDLE handle;
    PFILE_OBJECT fileObject;
    LARGE_INTEGER fileSize;
    DISK_LAYOUT layout;

    handle = NULL;
    fileObject = NULL;
    layout.DiskRuns = NULL;

    //
    // Attempt to open the requested file
    //
    status = OpenFileViaNormalPath("\\??\\C:\\Windows\\System32\\Drivers\\beep.sys", 
                                   OpenTypePatchOrCopy,
                                   &handle,
                                   &fileObject, 
                                   &size);
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to open beep.sys: %08x\n", status);
        goto Exit;
    }

    fileSize.QuadPart = size;

    //
    // Attempt to locate the disk runs for the file.
    //
    status = GetFileDiskRuns(handle, &fileSize, &layout);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to get disk runs for beep.sys: %08x\n", status);
        goto Exit;
    }

    NT_ASSERT(layout.DiskRuns != NULL);

    DBGPRINT("DmpFlt:  Beep.sys (size: %I64u) at offset %I64u\n", 
             size, 
             layout.DiskRuns[0].LogicalOffset);

Exit:

    if (handle != NULL)
    {
        ZwClose(handle);
    }

    if (fileObject != NULL)
    {
        ObDereferenceObject(fileObject);
    }

    if (layout.DiskRuns != NULL)
    {
        ExFreePool(layout.DiskRuns);
    }

    return status;
    
}
#endif

} // extern "C"