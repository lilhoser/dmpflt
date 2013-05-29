
/*!
    ------------------------------------------------------------
    @file       PostCrash.hpp
    
    @brief      Post-crash module header
    
    @details    Post crash handles executing file patch/copy ops
                that were staged during pre-crash.  All functions 
                in this file operate in CRASH mode, meaning HIGH_IRQL,
                synchronous I/O, uninterruptible single-thread, etc.
                This means severe restrictions on what kernel API's 
                are available. None of these functions should be
                called outside of the crash I/O path in crash mode.
                Any bugs in this code will cause the crash path itself
                to crash.  Depending on the bug type, the system might
                just reboot if no debugger is attached, or it might
                hang forever, or it might double fault, or...

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/
#include "PostCrash.hpp"

extern "C" {

//
// Pointer to our global context structure
//
extern PDMPFLT_CONTEXT g_Context;

/*!

    @brief This function handles carrying out a file copy or patch which was 
        staged by the pre-crash module.

    @details This function is called directly by our dump filter's DumpFinish 
        callback, after the dump stack has completed writing the crash dump 
        file and logging everything to the dump stack log.  When our DumpFinish 
        routine is called, crashdmp.sys is just about to finalize the log file via
        an internal function FinalizedLogFile(), which calls an internal read 
        routine to consume the log data immediately followed by a write routine 
        to finalize it back in the file.  We can manipulate this operation by 
        simply replacing the disk runs for the dump stack's log file to any file.

    @return N/A

*/
__checkReturn
NTSTATUS
ExecuteStagedOperation (
    VOID
    )
{
    PFILTER_CONTEXT context;
    NTSTATUS status;
    BOOLEAN restoreNeeded;
    PMAPPING_PAIR run;
    ULONG numRuns;
    PDISK_LAYOUT newLayout;
    PDISK_LAYOUT oldLayout;
    PREQUESTED_FILE_ATTRIBUTES requestedFile;
    PUCHAR target;
    ULONG i;

    restoreNeeded = FALSE;
    requestedFile = &g_Context->StagingInformation.RequestedFileAttributes;
    oldLayout = &g_Context->StagingInformation.OriginalFileLayout;
    newLayout = &requestedFile->Layout;
    run = newLayout->DiskRuns;
    numRuns = newLayout->NumDiskRuns;

    //
    // If there are no disk runs requested, this means pre-staging
    // of the requested file failed (not necessarily an error case
    // worthing of printing a debug message, though).
    //
    if (run == NULL || numRuns == 0)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // If the original dump stack log's disk runs were not saved, fail.
    //
    if (oldLayout->DiskRuns == NULL || oldLayout->NumDiskRuns == 0)
    {
        DBGPRINT("DmpFlt: No original disk runs, can't continue.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 

    //
    // Replace the log file disk runs stored in the context structure 
    // with the disk runs that describe the requested file.
    //
    status = ImplantDiskRuns(newLayout);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to implant disk runs for requested file: %08x\n", 
                 status);
        goto Exit;
    }

    restoreNeeded = TRUE;

    //
    // Use the logging function to read disk, but the
    // disk runs that function uses points to the requested file.
    // This places the contents of the requested/target file into
    // our global buffer pointer.
    //
    // NB: We rely on pre-staging to insure we don't stage a file
    // that is larger than our resident scratch buffer length.
    //
    status = ReadFileViaCrashPath();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: ReadLogDataFromDisk() failed with status %08x\n", status);
        goto Exit;
    }

    restoreNeeded = FALSE;

    DBGPRINT("DmpFlt: Successfully read requested file data off disk.\n");

    //
    // We are copying the contents to the dump stack log file, so restore
    // the original disk runs that point to the log file.
    //
    if (g_Context->StagingInformation.StagedOperation == OperationCopy)
    {
        status = ImplantDiskRuns(oldLayout);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("DmpFlt: Failed to restore disk runs for log file: %08x\n", 
                     status);
            goto Exit;
        }
    }
    //
    // If the desire is to overwrite the original file (ie, we are patching it),
    // do not restore original disk runs. Instead, modify the contents before
    // writing it back to disk.
    //
    else if (g_Context->StagingInformation.StagedOperation == OperationPatch)
    {
        //
        // We force a restore of the original log disk runs, because
        // we don't need to overwrite it.
        //
        restoreNeeded = TRUE;

        NT_ASSERT(requestedFile->OverwriteLength > 0);
        NT_ASSERT(g_Context->BufferSize > 
                 (requestedFile->OverwriteOffset + requestedFile->OverwriteLength));
                   
        //
        // Perform the patch
        //
        target = (PUCHAR)((ULONG_PTR)g_Context->Buffer + 
                          requestedFile->OverwriteOffset);

        for (i = 0; i < requestedFile->OverwriteLength; i++)
        {
            target[i] = requestedFile->OverwriteBytes[i];
        }
    }
    else
    {
        DBGPRINT("DmpFlt: Invalid or no operation specified\n");
        goto Exit;
    }

    //
    // Use the logging function to write the data we read (and potentially modified)
    // from the requested file back to the target file, which is either the
    // dumpstack.log.tmp file or the requested file itself (patched).
    //
    status = WriteFileViaCrashPath();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to write requested file data to disk: %08x\n", 
                 status);
        goto Exit;
    }

Exit:

    if (restoreNeeded != FALSE)
    {
        //
        // Restore the disk runs to the actual dump stack log file.
        //
        status = ImplantDiskRuns(oldLayout);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("DmpFlt: Failed to restore disk runs for log file: %08x\n", 
                     status);
            goto Exit;
        }
    }

    //
    // NB: We can't free OS-allocated buffer setup prior to crash
    // from our PreCrashStaging code b/c HIGH_IRQL 
    // (g_Context->RequestedFileLayout.DiskRuns)
    //

    return status;
}

/*!

    @brief This routine swaps the disk run structure stored inside the crashdmp.sys 
        global context structure, which originally pointed to the dump stack's log 
        file (c:\dumpstack.log.tmp).

    @param[in] NewLayout - The new disk runs to store in the context structure

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
ImplantDiskRuns (
    __in PDISK_LAYOUT NewLayout
    )
{
    PFILTER_CONTEXT context;
    PDISK_LAYOUT layout;
    NTSTATUS status;

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 

    NT_ASSERT(context != NULL);
    NT_ASSERT(context->Context != NULL);

    layout = (PDISK_LAYOUT)((ULONG_PTR)context->Context + LOGFILE_DISK_RUNS_OFFSET);

    if (layout == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        DBGPRINT("DmpFlt: Current dump stack log file has no layout!\n");
        goto Exit;
    }

    if (layout->NumDiskRuns <= 0)
    {
        status = STATUS_UNSUCCESSFUL;
        DBGPRINT("DmpFlt: Current dump stack log file has no runs!\n");
        goto Exit;
    }

    //
    // Overwrite with new layout
    // 
    // NB: We should ExFreePool(layout->DiskRuns), but we can't bc we're at HIGH IRQL!
    //
    layout->DiskRuns = NewLayout->DiskRuns;
    layout->NumDiskRuns = NewLayout->NumDiskRuns;    

    status = STATUS_SUCCESS;

Exit:

    return status;
}

/*!

    @brief This routine reads a file's contents by using the crash I/O path.  The
        file that is read is whatever is currently represented by the log file disk runs
        of crashdmp.sys's internal context structure.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
ReadFileViaCrashPath (
    VOID
    )
{
    PFILTER_CONTEXT context;
    NTSTATUS status;
    LARGE_INTEGER offset;
    PVOID crashRead;

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 
    crashRead = (PVOID)g_Context->CrashdmpInformation.CrashdmpReadLogDataFromDisk;

    NT_ASSERT(context != NULL);
    NT_ASSERT(context->Context != NULL);
    NT_ASSERT(crashRead != NULL);

    offset.LowPart = 0;
    offset.HighPart = 0;

    //
    // Use the crashdmp built-in routine to read the log data off disk.
    // We are in the crash dump I/O path at this point, so we are using
    // the crash dump stack not normal I/O path!
    //
    status = ((ReadLogDataFromDisk)crashRead)((PVOID)context->Context,
                                               g_Context->Buffer,
                                               0,
                                               0,
                                               offset);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: ReadLogDataFromDisk() failed with status %08x\n", status);
        goto Exit;
    }

Exit:

    return status;
}


/*!

    @brief This routine writes to a file using the crash I/O path.  The
        file that is written is whatever is currently represented by the 
        log file disk runs of crashdmp.sys's internal context structure.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
WriteFileViaCrashPath (
    VOID
    )
{
    PFILTER_CONTEXT context;
    NTSTATUS status;
    PVOID common;
    PVOID crashWrite;

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 
    crashWrite = (PVOID)g_Context->CrashdmpInformation.CrashdmpWriteLogDataToDisk;

    NT_ASSERT(context != NULL);
    NT_ASSERT(crashWrite != NULL);

    //
    // Hack:  Due to /LTCG optimizations in crashdmp.sys, this function
    // uses x86-only optimization of custom calling convention, which
    // stores one or more arguments in random registers.
    // The register here is subject to change in future binaries.
    //
    common = (PVOID)context->Context;
    __asm mov edi, common

    NT_ASSERT(common != NULL);

    //
    // Use the crashdmp built-in routine to write the log data to disk.
    // We are in the crash dump I/O path at this point, so we are using
    // the crash dump stack not normal I/O path!
    //
    status = ((WriteLogDataToDisk)crashWrite)(g_Context->Buffer, 0);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: WriteLogDataToDisk() failed with status %08x\n", status);
        goto Exit;
    }

Exit:

    return status;
}

/*!

    @brief This function is called by our dump filter's Dump_Write callback,
        FltDumpWrite, and appends the Ctf key to the dump MDL if the MDL
        is being written to the dump file.

    @details This function should ONLY be called after it has been verified
        that a file patch has been staged (ie, stage 3 of CTF). 

    @param[inout] DiskByteOffset - The partition-relative offset of the target
        of this write operation.
      
    @param[inout] Mdl - An MDL that describes and holds the contents of the data
        buffer being written at the supplied DiskByteOffset.

    @return N/A

*/
__checkReturn
NTSTATUS
AppendKeyToDumpWriteMdl (
    __inout PLARGE_INTEGER DiskByteOffset,
    __inout PMDL Mdl
    )
{
    NTSTATUS status;
    PMDL mdl;
    PDISK_LAYOUT layout;
    UCHAR key[KEY_SIZE];
    PVOID dstBuffer, srcBuffer;
    PPFN_NUMBER srcPfnArray, dstPfnArray;
    ULONG srcPfnCount, dstPfnCount;
    PREQUESTED_FILE_ATTRIBUTES requestedFile;

    NT_ASSERT(DiskByteOffset != NULL);
    NT_ASSERT(Mdl != NULL);

    requestedFile = &g_Context->StagingInformation.RequestedFileAttributes;
    layout = &requestedFile->Layout;
    status = STATUS_SUCCESS;

    NT_ASSERT(layout->DiskRuns != NULL);

    //
    // Don't even consider MDL's describing buffers too small for the CTF key
    //
    if (Mdl->ByteCount < KEY_SIZE)
    {
        DBGPRINT("DmpFlt: Target MDL too small to contain key.\n");
        goto Exit;
    }

    //
    // If this write callback is from a patch operation to a staged file
    // currently IN PROGRESS, we DONT want to dump the key!
    // (otherwise, we would overwrite part of the staged file with the key)
    //
    if (DumpWriteInRange(DiskByteOffset, layout) != FALSE)
    {
        DBGPRINT("DmpFlt: Not appending key to dump write MDL within range " 
                 "of the target of a staged patch operation.\n");
        goto Exit;
    }

    //
    // If this write callback is from normal dump stack logging, ie
    // crashdmp.sys trying to write to its log, we DONT want to dump
    // the key! (otherwise we'd append the key to c:\dumpstack.log.tmp)
    //
    layout = &g_Context->StagingInformation.OriginalFileLayout;

    //
    // The original dump file's runs are ALWAYS saved when
    // a patch operation is staged.
    //
    NT_VERIFY(layout->DiskRuns != NULL);

    if (DumpWriteInRange(DiskByteOffset, layout))    
    {
        DBGPRINT("DmpFlt: Not appending key to dump write MDL within range " 
                 "of dump stack logging file.\n");
        goto Exit;
    }

    srcBuffer = (PVOID)(((ULONG_PTR)Mdl->MappedSystemVa & 0xFFFFF000) + Mdl->ByteOffset);

    //
    // If this is a dump write for the dump file header, we don't mess
    // with it to avoid corrupting the dump file.
    //
    if (((*(PULONG)srcBuffer) == 'EGAP') &&
        ((*(PULONG)((ULONG_PTR)srcBuffer + sizeof(ULONG))) == 'PMUD'))
    {
        DBGPRINT("DmpFlt: Not appending key to dump MDL containing dump "
                 "file header\n");
        goto Exit;
    }
    
    //
    // We have a candidate MDL suitable for containing the CTF key;
    // read it from the static location on disk.
    //
    status = GetKey(key);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to get key: %08x\n", status);
        goto Exit;
    }

    //
    // The scratch mdl was allocated and mapped in DriverEntry and
    // already describes our global context buffer.
    //
    mdl = g_Context->CtfStateInformation.KeyMdl;

    NT_ASSERT(mdl != NULL);

    //
    // The size of the dump MDL buffer should never exceed our global
    // scratch buffer, bc we followed MSDN docs that require us to
    // allocate a large enough size for any dump transfer.  Typically
    // a dump transfer is one page (4096) whereas our scratch buffer 
    // is PAGE_SIZE * MaxPagesPerWrite (16)
    //
    NT_ASSERT(Mdl->ByteCount <= mdl->ByteCount);

    //
    // In the next few code blocks, I'm mirroring what I see done in bitlocker's
    // dump filter, dumpfve!DoubleBufferMdl()...It would be nice to use Mm* 
    // MDL macros here, but they cant be used past DISPATCH_LEVEL...
    //

    //
    // First, copy what's in the dump MDL into our scratch buffer MDL.
    // (we are making a "double buffer" or "secondary buffer")
    //
    dstBuffer = (PVOID)(((ULONG_PTR)mdl->MappedSystemVa & 0xFFFFF000) + mdl->ByteOffset);
    RtlMoveMemory(dstBuffer, srcBuffer, Mdl->ByteCount);

    //
    // Overwrite a portion of the current dump buffer with our key,
    // starting from position 0 in that buffer.
    //
    RtlMoveMemory(dstBuffer, key, KEY_SIZE);

    //
    // Get the PFN array that describes physical pages mapped to
    // the dump MDL's virtual address.  We will update this array.
    // NB: We cannot use MmBuildMdlForNonPagedPool b/c HIGH_IRQL
    // but MmGetMdlPfnArray() is safe at any IRQL.
    //
    dstPfnArray = MmGetMdlPfnArray(Mdl);
    dstPfnCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(srcBuffer, Mdl->ByteCount);

    //
    // Get the number of PFN's we need to overwrite in the dump
    // MDL pfn array by querying our scratch buffer mdl.
    //
    srcPfnArray = MmGetMdlPfnArray(mdl);
    srcPfnCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(dstBuffer, mdl->ByteCount);

    NT_ASSERT(dstPfnCount > 0);
    NT_ASSERT(srcPfnCount > 0);

    //
    // Again, because our buffer is allocated PAGE_SIZE * MaxPagesPerWrite,
    // the dump MDL pfn array always has fewer elements than ours.
    //
    NT_ASSERT(dstPfnCount <= srcPfnCount);

    RtlCopyMemory(dstPfnArray, srcPfnArray, dstPfnCount * sizeof(PFN_NUMBER));

    //
    // Swap the buffers in the dump MDL to point to our mdl's buffers
    // Note: we dont change Mdl->ByteCount because we cannot alter
    // the size of the transfer (dump mode rule!).
    //
    Mdl->MappedSystemVa = mdl->MappedSystemVa;
    Mdl->StartVa = mdl->StartVa;
    Mdl->ByteOffset = mdl->ByteOffset;

    g_Context->CtfStateInformation.KeyDumped = TRUE;

    DBGPRINT("DmpFlt: Successfully dumped key.\n");

Exit:

    return status;
}


/*!

    @brief Extracts the CTF key which is stored at a static offset on disk.

    @details This function is called in preparation for appending the key to 
        a dump MDL buffer, if the user has finished the challenge.

    @param[__out_bcount(KEY_SIZE)] Key - Stores the key on success.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
GetKey (
    __out_bcount(KEY_SIZE) PUCHAR Key
    )
{
    NTSTATUS status;
    MAPPING_PAIR run;
    DISK_LAYOUT newLayout;
    PDISK_LAYOUT oldLayout;
    BOOLEAN restoreNeeded;
    
    restoreNeeded = FALSE;
    oldLayout = &g_Context->StagingInformation.OriginalFileLayout;
    run.LogicalOffset = BEEP_SYS_LOGICAL_OFFSET;
    run.SectorSize = BEEP_SYS_SIZE;
    newLayout.NumDiskRuns = 1;
    newLayout.DiskRuns = &run;

    RtlZeroMemory(Key, KEY_SIZE);

    //
    // Replace the log file disk runs stored in the context structure 
    // with the disk runs that describe the requested file.
    //
    status = ImplantDiskRuns(&newLayout);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to implant disk runs to dump key: %08x\n", status);
        goto Exit;
    }

    restoreNeeded = TRUE;
    RtlZeroMemory(g_Context->Buffer, g_Context->BufferSize);

    //
    // Use the logging function to read disk, but the
    // disk runs that function uses points to the requested file.
    // This places the contents of the requested/target file into
    // our global buffer pointer.
    //
    status = ReadFileViaCrashPath();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: ReadLogDataFromDisk() failed with status %08x\n", status);
        goto Exit;
    }

    //  
    // The operation copied the entire file into the buffer.
    // We just want the key.
    //
    RtlCopyMemory(Key, g_Context->Buffer + KEY_OFFSET, KEY_SIZE);
    status = STATUS_SUCCESS;

Exit:

    //
    // Restore the disk runs to the actual dump stack log file.
    //
    if (restoreNeeded != FALSE)
    {
        status = ImplantDiskRuns(oldLayout);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("DmpFlt: Failed to restore disk runs for log file: %08x\n", status);
            goto Exit;
        }
    }

    return status;
}

/*!

    @brief Determines if the supplied partition-relative disk offset falls
        within the range of any disk run in the supplied DISK_LAYOUT
        structure.

    @param[in] RequestedDiskOffset - the disk offset

    @param[in] Layout - the disk run mapping structure

    @return TRUE if in range, FALSE if not

*/
BOOLEAN
DumpWriteInRange (
    __in PLARGE_INTEGER RequestedDiskOffset,
    __in PDISK_LAYOUT Layout
    )
{
    ULONG i;
    LONGLONG start, end;

    NT_ASSERT(Layout != NULL);
    NT_ASSERT(Layout->DiskRuns != NULL);
          
    for (i = 0; i < Layout->NumDiskRuns; i++)
    {
        start = (LONGLONG)Layout->DiskRuns[i].LogicalOffset;
        end = (LONGLONG)start + Layout->DiskRuns[i].SectorSize;

        if ((RequestedDiskOffset->QuadPart >= start) && 
            (RequestedDiskOffset->QuadPart < end))
        {
            return TRUE;
        }
    }

    return FALSE;    
}

/*!

    @brief Prints the CTF banner to the screen

    @return N/A

*/
VOID
PrintCtfBanner (
    VOID
    )
{
    PVOID clearScreen;
    UNICODE_STRING banner;
    PVOID acquire;
    
    clearScreen = (PVOID)g_Context->KernelInformation.BgpClearScreen;

    NT_ASSERT(clearScreen != NULL);

    RtlInitUnicodeString(&banner, g_Banner);  

    //
    // Not entirely sure why this is needed, but KiDisplayBlueScreen does it
    // before using any bcp* functions...
    //
    acquire = (PVOID)g_Context->KernelInformation.InbvAcquireDisplayOwnership;
    NT_ASSERT(acquire != NULL);
    ((InbvAcquireDisplayOwnership)acquire)();

    //
    // windows uses 0xff2067b2 here, which seems to correspond to RGB(32,103,178)..
    // however, I wasn't able to use other RGB values here.
    //
    ((BgpClearScreen)clearScreen)(0xff2067b2);
    
    PrintMessageBcp(&banner, BANNER_FONT_SIZE, BANNER_Y, 1);

    return;
}

/*!

    @brief Prints the main CTF message body to the screen.

    @return N/A

*/
VOID
PrintCtfMessage (
    VOID
    )
{
    UNICODE_STRING message;
    PVOID acquire;

    //
    // Not entirely sure why this is needed, but KiDisplayBlueScreen does it
    // before using any bcp* functions...
    //
    acquire = (PVOID)g_Context->KernelInformation.InbvAcquireDisplayOwnership;
    NT_ASSERT(acquire != NULL);
    ((InbvAcquireDisplayOwnership)acquire)();

    //
    // Set the blue screen message based on CTF stage completed.
    //
    switch (g_Context->CtfStateInformation.CtfStageCompleted)
    {
        case ChallengeBegin:
        {
            //PrintMessageInbv("U MAD YET BRAH? Dump stack logging is disabled!", MESSAGE_REPEAT);
            //return;
            RtlInitUnicodeString(&message, L"U MAD YET BRAH? Dump stack logging is disabled!");
            break;
        }
        case ChallengeStage1:
        {
            //
            // If they successfully staged a file, but it wasn't key.txt,
            // they get a nicer message.
            //
            if (g_Context->StagingInformation.StagedOperation == OperationCopy)
            {
                RtlInitUnicodeString(&message, L"File copied.  Cool story, bro.");
            }
            else
            {
                RtlInitUnicodeString(&message, L"No file specified yet!!");
            }

            break;
        }
        case ChallengeStage2:
        {
            RtlInitUnicodeString(&message, L"Key file is empty, nice try!  " \
                                 L"[path]|[offset]|[byte1],[byte2]...");
            break;
        }
        case ChallengeStage3:
        {
            RtlInitUnicodeString(&message, L"Troll complete.  We got a badass here.");    
            break;
        }
        default:
        {
            DBGPRINT("DmpFlt: CTF stage corrupt!\n");
            return;
        }
    }

    PrintMessageBcp(&message, MESSAGE_FONT_SIZE, MESSAGE_Y, MESSAGE_REPEAT);

    return;
}

/*!

    @brief Uses kernel's internal Bcp* functions to write a string to the screen.

    @details Many aspects of these functions are undocumented and guessed.  For example,
        the prototypes for BcpDisplayCriticalString() and BcpSetCursorPosition aren't
        entirely understood.  Any changes at all to this function such as changing a 
        message to be printed should be carefully debugged!  Note that we can't call these
        screen display functions when it's a manually initiated crash from debugger (.crash)
        bc kernel won't init the library in that case!!  Leave as bug for now.

    @param[in] Message - the message to print
    
    @param[in] FontSize - the size of font to use

    @param[in] Vertical - Y offset to print at
    
    @param[in] Count - how many times to print the message over itself (delay effect)

    @return N/A

*/
VOID
PrintMessageBcp (
    __in PUNICODE_STRING Message,
    __in ULONG FontSize,
    __in ULONG Vertical,
    __in ULONG Count
    )
{
    PVOID displayString;
    PVOID setCursorPosition;
    ULONG i;
    ULONG unknown;
    
    unknown = 0;
    displayString = (PVOID)g_Context->KernelInformation.BcpDisplayCriticalString;
    setCursorPosition = (PVOID)g_Context->KernelInformation.BcpSetCursorPosition;

    NT_ASSERT(displayString != NULL);
    NT_ASSERT(setCursorPosition != NULL);

    //
    // Print message, overwriting repeatedly to delay so user sees it
    //
    for (i = 0; i < Count; i++)
    {   
        ((BcpSetCursorPosition)setCursorPosition)(0x50, Vertical, 0);
        ((BcpDisplayCriticalString)displayString)(Message, FontSize, unknown);
    }

    return;
}

/*!

    @brief Uses kernel's exported Inbv* functions to write a string to the screen.

    @param[in] Message - the message to print
    
    @param[in] FontSize - the size of font to use
    
    @param[in] Count - how many times to print the message over itself (delay effect)

    @return N/A

*/
VOID 
PrintMessageInbv (
    __in PCCHAR Message,
    __in ULONG Count
    )
{
    PVOID acquire;
    PVOID reset;
    PVOID enable;
    PVOID scroll;
    PVOID display;
    PVOID fill;
    PVOID text;
    ULONG i;
    
    //
    // Some of the Inbv* API's are wrappers around internal drawing functions:
    //      nt!InbvAcquireDisplayOwnership --> nt!BgkAcquireDisplayOwnership
    //      nt!InbvSetTextColor --> nt!BgkSetTextColor
    //      nt!InbvDisplayString --> nt!BgkDisplayString
    //
    acquire = (PVOID)g_Context->KernelInformation.InbvAcquireDisplayOwnership;
    reset = (PVOID)g_Context->KernelInformation.InbvResetDisplay;
    enable = (PVOID)g_Context->KernelInformation.InbvEnableDisplayString;
    scroll = (PVOID)g_Context->KernelInformation.InbvSetScrollRegion;
    display = (PVOID)g_Context->KernelInformation.InbvDisplayString;
    fill = (PVOID)g_Context->KernelInformation.InbvSolidColorFill;
    text = (PVOID)g_Context->KernelInformation.InbvSetTextColor;

    for (i = 0; i < Count; i++)
    {
        ((InbvAcquireDisplayOwnership)acquire)();
        ((InbvResetDisplay)reset)();
        ((InbvEnableDisplayString)enable)(TRUE);
        ((InbvSetScrollRegion)scroll)(0, 0, 639, 479);
        ((InbvSetTextColor)text)(15);
        ((InbvDisplayString)display)(Message);
        ((InbvSolidColorFill)fill)(0, 0, 640, 480, 4);
    }

    return;
}

} // extern "C"