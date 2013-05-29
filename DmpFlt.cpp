/*!
    ------------------------------------------------------------
    @file       DmpFlt.cpp
    
    @brief      DmpFlt crash dump filter module implementation
    
    @details    The DmpFlt module contains DriverEntry and other
                core functions for crash dump filter callbacks.
                Note that all crash dump filter callbacks defined
                below, save Dump_Unload, are called in crash mode
                which means all of the restrictions outlined in
                the file header for PostCrash.hpp!

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/

#include "DmpFlt.hpp"

extern "C"
{

//
// Pointer to our global context structure
//
PDMPFLT_CONTEXT g_Context = NULL;

//
// A global callback structure that notifies us when kernel phase 1
// initialization is complete, indicating it's safe to finish
// initializing our driver.
//
PCALLBACK_OBJECT g_Callback = NULL;
PVOID g_CallbackHandle = NULL;

/*!

    @brief The entry point for the driver

    @details Being a crash dump filter driver, the function signature for this driver
        is non-standard, as the documentation here states.  Technically the        
        annotations are incorrect, as RegistryPath, which is actually a pointer
        to a FILTER_INITIALIZATION_DATA structure, is written to as required by
        the crash dump rules.  Also, because DriverEntry here is called by the kernel
        early in phase 1 initialization since we are in the crash stack, we are loaded 
        very early on and it's not suitable to do some of our init in DriverEntry.  
        Therefore we register a callback and perform init then.

    @param[in] DriverObject - Pointer to a FILTER_EXTENSION structure

    @param[in] RegistryPath - Pointer to a FILTER_INITIALIZATION_DATA structure

    @return NTSTATUS code

*/  
NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    PFILTER_INITIALIZATION_DATA initializationData;
    PFILTER_EXTENSION extension;
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;

    NT_ASSERT(DriverObject != NULL);
    NT_ASSERT(RegistryPath != NULL);    

    initializationData = (PFILTER_INITIALIZATION_DATA)RegistryPath;
    extension = (PFILTER_EXTENSION)DriverObject;

    //
    // Create a callback to be notified by the kernel when it has
    // completed phase1 initialization, which is when the crash dump
    // stack is loaded and initialized.  This reduces the likelihood
    // that we will cause instability.
    //
    RtlInitUnicodeString(&name, L"\\Callback\\Phase1InitComplete");

    InitializeObjectAttributes(&attributes,
                               &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
                               
    status = ExCreateCallback(&g_Callback, &attributes, TRUE, FALSE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to create kernel callback: %08x\n", status);
        g_Callback = NULL;
        goto Exit;
    }

    g_CallbackHandle = ExRegisterCallback(g_Callback, Initialize, NULL);
    
    if (g_CallbackHandle == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        DBGPRINT("DmpFlt: Failed to register callback!\n");
        goto Exit;
    }

    //
    // Allocate our global extension structure
    //
    g_Context = (PDMPFLT_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, 
                                                       sizeof(DMPFLT_CONTEXT),
                                                       DMPFLT_TAG);

    if (g_Context == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DBGPRINT("DmpFlt: Failed to allocate context structure.\n");
        goto Exit;
    }

    RtlZeroMemory(g_Context, sizeof(DMPFLT_CONTEXT));

    g_Context->InitializationData = initializationData;
    g_Context->Extension = extension;    

    //
    // Fill in our filter initialization data, notifying the crash
    // dump stack of our capabilities.
    //
    initializationData->MajorVersion = DUMP_FILTER_MAJOR_VERSION;
    initializationData->MinorVersion = DUMP_FILTER_MINOR_VERSION;
    initializationData->DumpStart = FltDumpStart;
    initializationData->DumpFinish = FltDumpFinish;
    initializationData->DumpUnload = FltDumpUnload;
    initializationData->DumpRead = FltDumpRead;
    initializationData->DumpWrite = FltDumpWrite;
    initializationData->DumpData = NULL;  // TODO:  pass our context here
    initializationData->Flags = DUMP_FILTER_FLAG_SYSTEM_SUPPORT_READ;

    status = STATUS_SUCCESS;

    DBGPRINT("DmpFlt: DriverEntry successful.\n");

Exit:

    if (!NT_SUCCESS(status))
    {
        Cleanup();
    }

    return status;
}

/*!

    @brief This function completes our required initialization.

    @details This code, originally in DriverEntry, was moved out into a separate
        function, called by the kernel after phase1 initialization is completed.
        Since we are in the crash stack, we are loaded very early on and it's not
        suitable to do some of our init in DriverEntry.

    @param[in] CallbackContext - Unused

    @param[in] Argument1 - Unused

    @param[in] Argument2 - Unused

    @return NTSTATUS code

*/
VOID
Initialize (
    __in_opt PVOID CallbackContext,
    __in_opt PVOID Argument1,
    __in_opt PVOID Argument2
    )
{
    NTSTATUS status;    
    PFILTER_EXTENSION filterExtension;
    PFILTER_INITIALIZATION_DATA initializationData;
    FILTER_DUMP_TYPE dumpType;
    OBJECT_ATTRIBUTES attributes;
    HANDLE thread;

    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    filterExtension = g_Context->Extension;
    initializationData = g_Context->InitializationData;
    dumpType = filterExtension->DumpType;

    DBGPRINT("DmpFlt: Kernel initialization complete, finishing init...\n");
    DBGPRINT("DmpFlt: Received filter initdata at %p and extension at %p:\n", 
             initializationData, 
             filterExtension);
    DBGPRINT("DmpFlt:\tDumpType:  %s\n", 
             dumpType == DumpTypeCrashdump ? "Crash" : "Hiber");
    DBGPRINT("DmpFlt:\tDeviceObject:  %p\n", filterExtension->DeviceObject);
    DBGPRINT("DmpFlt:\tDisk Size:  %I64u\n", filterExtension->DiskSize.QuadPart);

    NT_ASSERT(filterExtension->DeviceObject != NULL);

    //
    // Setup our global context structure.
    //
    status = InitializeContext();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Initialization failed.\n");
        goto Exit;
    }

    //
    // Initialize timers
    //
    InitializeTimers();

    //
    // Initialize an event that our worker thread
    // can wait for to know when to stop.
    //
    KeInitializeEvent(&g_Context->TimerInformation.StopTimer, 
                      NotificationEvent,
                      FALSE);

    //  
    // Create a worker thread to wait on timer events
    //
    InitializeObjectAttributes(&attributes,
                               NULL,
                               OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = PsCreateSystemThread(&thread,
                                  THREAD_ALL_ACCESS,
                                  &attributes,
                                  NULL,
                                  NULL,
                                  TimerWait,
                                  NULL);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to create worker thread: %08x\n", status);
        goto Exit;
    }

    status = ObReferenceObjectByHandle(thread,
                                       THREAD_ALL_ACCESS,
                                       *PsThreadType,
                                       KernelMode,
                                       &g_Context->TimerInformation.WorkerThread,
                                       NULL);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Failed to take reference on worker thread: %08x\n", status);
        goto Exit;
    }

    ZwClose(thread);

#ifdef DBG
    status = GetBeepSysInformation();
#endif

Exit:

    return;
}


/*!

    @brief Releases all driver resources

    @details This function is called only from our Unload routine, which is only
        ever called by crashdmp.sys when it is safe to do so.

    @return N/A

*/
VOID
Cleanup (
    VOID
    )
{
    NTSTATUS status;
    PMAPPING_PAIR run;

    DBGPRINT("DmpFlt: Cleaning up...\n");

    //
    // This releases our kernel phase1 init callback.
    //
    if (g_Callback != NULL)
    {
        ObDereferenceObject(g_Callback);
    }

    if (g_CallbackHandle != NULL)
    {
        ExUnregisterCallback(g_CallbackHandle);
    }

    //
    // Everything else we need to cleanup is stored in
    // our global context, which if NULL, indicates 
    // there is nothing to cleanup.
    //
    if (g_Context == NULL)
    {
        return;
    }
    
    //
    // Tear down worker thread
    //
    if (g_Context->TimerInformation.WorkerThread != NULL)
    {
        //
        // Signal it to stop waiting
        //
#pragma prefast(suppress: 28160, "KeWait() call immediately follows")
        KeSetEvent(&g_Context->TimerInformation.StopTimer, 0, TRUE);

        //
        // Wait for the thread to die
        //
        status = KeWaitForSingleObject(g_Context->TimerInformation.WorkerThread, 
                                       Executive,
                                       KernelMode,
                                       FALSE,    
                                       NULL);
  
        if (status != STATUS_SUCCESS)
        {
            DBGPRINT("DmpFlt: Failed to wait for worker thread: %08x\n", status);
        }

        ObDereferenceObject(g_Context->TimerInformation.WorkerThread);

        g_Context->TimerInformation.WorkerThread = NULL;
    }

    if (g_Context->TimerInformation.TimerSet != FALSE)
    {
        CancelTimers();
        g_Context->TimerInformation.TimerSet = FALSE;
    }

    //
    // Free any disk run allocation
    // NB: It's os-allocated, so dont use our tag.
    //
    run = g_Context->StagingInformation.RequestedFileAttributes.Layout.DiskRuns;

    if (run != NULL)
    {
        ExFreePool(run);
        run = NULL;
    }

    //
    // Free explicitly allocated runs
    //
    run = g_Context->StagingInformation.OriginalFileLayout.DiskRuns;

    if (run != NULL)
    {
        ExFreePoolWithTag(run, DMPFLT_TAG);
        run = NULL;
    }

    //
    // Release MDL
    //
    if (g_Context->CtfStateInformation.KeyMdl != NULL)
    {
        IoFreeMdl(g_Context->CtfStateInformation.KeyMdl);
    }

    if (g_Context->Buffer != NULL)
    {
        ExFreePoolWithTag(g_Context->Buffer, DMPFLT_TAG);
        g_Context->Buffer = NULL;
    }

    ExFreePoolWithTag(g_Context, DMPFLT_TAG);
    g_Context = NULL;

    DBGPRINT("DmpFlt: Done.\n");

    return;
}


/*!

    @brief Initializes required fields in our global context structure.

    @return NTSTATUS code

*/
__checkReturn
NTSTATUS
InitializeContext (
    VOID
    )
{
    NTSTATUS status;
    ULONG_PTR imageBase;
    ULONG_PTR kernelBase;

    NT_ASSERT(g_Context != NULL);

    status = Is64bitProcess(NULL, &g_Context->HostInformation.Is64Bit);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not determine platform bitness.\n");
        goto Exit;
    }

    //
    // Allocate our scratch buffer for use in dump callbacks.
    //
    g_Context->BufferSize = g_Context->InitializationData->MaxPagesPerWrite * PAGE_SIZE;
    g_Context->Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 
                                                       g_Context->BufferSize,
                                                       DMPFLT_TAG);

    if (g_Context->Buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DBGPRINT("DmpFlt: Failed to allocate scratch buffer.\n");
        goto Exit;
    }

    RtlZeroMemory(g_Context->Buffer, g_Context->BufferSize);

    //
    // Allocate an MDL that will be used at crash time to
    // dump the CTF key.
    //
    g_Context->CtfStateInformation.KeyMdl = IoAllocateMdl(g_Context->Buffer, 
                                                          g_Context->BufferSize, 
                                                          FALSE,
                                                          FALSE, 
                                                          NULL);

    if (g_Context->CtfStateInformation.KeyMdl == NULL)
    {
        DBGPRINT("DmpFlt: Could not allocate key MDL\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit; 
    }

    MmBuildMdlForNonPagedPool(g_Context->CtfStateInformation.KeyMdl);

    //
    // Locate crashdmp.sys load address
    //
    status = FindDriverByName("crashdmp.sys", &imageBase);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate crashdmp.sys.\n");
        goto Exit;  
    }

    //
    // Locate ntoskrnl.exe load address
    //
    status = FindDriverByName("ntoskrnl.exe", &kernelBase);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate ntoskrnl.exe.\n");
        goto Exit;  
    }

    NT_ASSERT(kernelBase > 0);

    //
    // Locate crashdmp!ReadLogDataFromDisk()
    //
    status = ScanDriverSection(".text",
                               5,
                               imageBase, 
                               READLOGDATAFROMDISK_MAGIC, 
                               READLOGDATAFROMDISK_DISTANCE,
                               &g_Context->CrashdmpInformation.CrashdmpReadLogDataFromDisk);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate crashdmp!ReadLogDataFromDisk().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->CrashdmpInformation.CrashdmpReadLogDataFromDisk > 0);

    //
    // Locate crashdmp!ClearLogFile()
    //
    status = ScanDriverSection(".text",
                               5,
                               imageBase, 
                               CLEARLOGFILE_MAGIC, 
                               CLEARLOGFILE_DISTANCE,
                               &g_Context->CrashdmpInformation.CrashdmpClearLogFile);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate crashdmp!ClearLogFile().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->CrashdmpInformation.CrashdmpClearLogFile > 0);

    //
    // Locate crashdmp!WriteLogDataToDisk()
    //
    status = ScanDriverSection(".text",
                               5,
                               imageBase, 
                               WRITELOGDATATODISK_MAGIC, 
                               WRITELOGDATATODISK_DISTANCE,
                               &g_Context->CrashdmpInformation.CrashdmpWriteLogDataToDisk);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate crashdmp!WriteLogDataToDisk().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->CrashdmpInformation.CrashdmpWriteLogDataToDisk > 0);

    //
    // Locate ntoskrnl!BcpDisplayCriticalString
    //
    status = ScanDriverSection(".text",
                               5,
                               kernelBase, 
                               NTOS_BCPDISPLAYSTR_MAGIC, 
                               NTOS_BCPDISPLAYSTR_DISTANCE,
                               &g_Context->KernelInformation.BcpDisplayCriticalString);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate ntoskrnl!BcpDisplayCriticalString().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->KernelInformation.BcpDisplayCriticalString > 0);

    //
    // Locate ntoskrnl!BcpDisplayCriticalCharacter
    //
    status = ScanDriverSection(".text",
                               5,
                               kernelBase, 
                               NTOS_BCPDISPLAYCHAR_MAGIC, 
                               NTOS_BCPDISPLAYCHAR_DISTANCE,
                               &g_Context->KernelInformation.BcpDisplayCriticalCharacter);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate ntoskrnl!BcpDisplayCriticalCharacter().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->KernelInformation.BcpDisplayCriticalCharacter > 0);

    //
    // Locate ntoskrnl!BcpSetCursorPosition
    //
    status = ScanDriverSection(".text",
                               5,
                               kernelBase, 
                               NTOS_BCPSETCURSORPOSITION_MAGIC, 
                               NTOS_BCPSETCURSORPOSITION_DISTANCE,
                               &g_Context->KernelInformation.BcpSetCursorPosition);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate ntoskrnl!BcpSetCursorPosition().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->KernelInformation.BcpSetCursorPosition > 0);

    //
    // Locate ntoskrnl!BgpClearScreen
    //
    status = ScanDriverSection(".text",
                               5,
                               kernelBase, 
                               NTOS_BGPCLEAR_MAGIC, 
                               NTOS_BGPCLEAR_DISTANCE,
                               &g_Context->KernelInformation.BgpClearScreen);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Could not locate ntoskrnl!BgpClearScreen().\n");
        goto Exit;
    }

    NT_ASSERT(g_Context->KernelInformation.BgpClearScreen > 0);

    //
    // Locate exported Inbv* display functions
    //
    if ((GetKernelFunction(L"InbvDisplayString", 
                           &g_Context->KernelInformation.InbvDisplayString) == FALSE) ||
        (GetKernelFunction(L"InbvResetDisplay", 
                           &g_Context->KernelInformation.InbvResetDisplay) == FALSE) ||
        (GetKernelFunction(L"InbvSetScrollRegion", 
                           &g_Context->KernelInformation.InbvSetScrollRegion) == FALSE) ||
        (GetKernelFunction(L"InbvEnableDisplayString", 
                           &g_Context->KernelInformation.InbvEnableDisplayString) == FALSE) ||
        (GetKernelFunction(L"InbvAcquireDisplayOwnership", 
                           &g_Context->KernelInformation.InbvAcquireDisplayOwnership) == FALSE) ||
        (GetKernelFunction(L"InbvSolidColorFill", 
                           &g_Context->KernelInformation.InbvSolidColorFill) == FALSE) ||
        (GetKernelFunction(L"InbvSetTextColor", 
                           &g_Context->KernelInformation.InbvSetTextColor) == FALSE))
    {
        status = STATUS_UNSUCCESSFUL;
        DBGPRINT("DmpFlt: Could not locate a required Inbv* function.\n");
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    if (!NT_SUCCESS(status))
    {
        Cleanup();
    }

    return status;

}

/*!

    @brief Attemps to retrieve the address of a kernel export by name.

    @param[in] Name - The name of the exported function
   
    @param[out] Address - The address or NULL if not found.

    @return TRUE if the function was found, FALSE if not

*/
BOOLEAN
GetKernelFunction (
    __in PWCHAR Name,
    __out PULONG_PTR Address
    )
{
    UNICODE_STRING function;
    PVOID pointer;

    NT_ASSERT(Address != NULL);

    *Address = 0;

    RtlInitUnicodeString(&function, Name);

    pointer = MmGetSystemRoutineAddress(&function);

    if (pointer == NULL)
    {
        return FALSE;
    }

    *Address = (ULONG_PTR)pointer;

    return TRUE;   
}

/*!

    @brief The crash dump filter Dump_Start callback routine

    @details This function is called by crashdmp.sys when a bugcheck or hibernation
        event has occured and after the crashdmp.sys driver has initialized itself.

    @param[in] FilterExtension - Pointer to our FILTER_EXTENSION structure

    @return NTSTATUS code

*/  
NTSTATUS
FltDumpStart (
    __in PFILTER_EXTENSION FilterExtension
    )
{
    DBG_UNREFERENCED_PARAMETER(FilterExtension);

    return STATUS_SUCCESS;
}
    
/*!

    @brief The crash dump filter Dump_Finish callback routine

    @details This function is called by crashdmp.sys after all data has been written
        to the dump file and just before the log file (if enabled) has been 
        finalized.  This is the safest point to overwrite the DumpStack.log.tmp
        contents. We also write any CTF message to the screen here.

    @param[in] FilterExtension - Pointer to our FILTER_EXTENSION structure

    @return NTSTATUS code

*/
NTSTATUS
FltDumpFinish (
    __in PFILTER_EXTENSION FilterExtension
    )
{
    NTSTATUS status;    

    status = STATUS_SUCCESS;

    DBG_UNREFERENCED_PARAMETER(FilterExtension);

    DBGPRINT("DmpFlt: FltDumpFinish() called\n");

    //
    // Print CTF messages
    //
    // @TODO:  I wasn't able to figure out why, but for whatever reason,
    // trying to use the kernel screen functions at this stage of the
    // challenge causes a crash in this code path.  The stack trace
    // makes no sense, and I was not able to find any possible cause.
    // This is particularly unsettling because this code path where the
    // user has not enabled crash dump logging (the first stage of the CTF)
    // does little to nothing at all.  My only guess is there is somehow
    // some stack corruption in my code somewhere along this path.
    //
    if (g_Context->CtfStateInformation.CtfStageCompleted != ChallengeBegin)
    {
        //PrintCtfBanner();
        //PrintCtfMessage();
    }

    //
    // Our only indication that the log file is enabled and
    // ready for us to replace is that we have already successfully
    // exposed it to user mode.
    //
    if (g_Context->StagingInformation.LogFileExposed == FALSE)
    {
        DBGPRINT("DmpFlt: Log file not ready, exiting.\n");
        goto Exit;
    }
    
    DBGPRINT("DmpFlt: Attempting to execute any staged operation...\n");

    status = ExecuteStagedOperation();

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("DmpFlt: Operation failed: %08x\n", status);
        goto Exit;
    }

    DBGPRINT("DmpFlt: Success!\n");

Exit:

    //
    // Even if we fail, don't propagate
    //
    return STATUS_SUCCESS;
}

/*!

    @brief The crash dump filter Dump_Unload callback routine

    @details This function is called by crashdmp.sys only when the crash path is 
        being disabled or resuming from hibernation.  We can safely call our 
        Cleanup() on our resources since we wont be at high irql.

    @param[in] FilterExtension - Pointer to our FILTER_EXTENSION structure

    @return NTSTATUS code

*/
NTSTATUS
FltDumpUnload (
    __in PFILTER_EXTENSION FilterExtension
    )
{
    DBG_UNREFERENCED_PARAMETER(FilterExtension);

    DBGPRINT("DmpFlt: Unloading..\n");

    Cleanup();

    return STATUS_SUCCESS;
}


/*!

    @brief The crash dump filter Dump_Write callback routine

    @details This function is called by crashdmp.sys for every write operation in
        the crash I/O path.  Filters are given the opportunity to do anything
        they want with the data buffer in the supplied MDL, which contains 
        data the OS is writing to the dump or hiber file.  Typically a WDE
        driver will encrypt the contents.  Note that the inout annotation for
        the DiskByteOffset is wrong according to MSDN docs, which states filters
        CANNOT modify the offset value.

    @param[in] FilterExtension - Pointer to our FILTER_EXTENSION structure

    @param[inout] DiskByteOffset - The partition-relative offset of the target
        of this write operation.
      
    @param[inout] Mdl - An MDL that describes and holds the contents of the data
        buffer being written at the supplied DiskByteOffset.

    @return NTSTATUS code

*/
NTSTATUS
FltDumpWrite (
    __in PFILTER_EXTENSION FilterExtension,
    __inout PLARGE_INTEGER DiskByteOffset,
    __inout PMDL Mdl
    )
{
    NTSTATUS status;
    PDISK_LAYOUT layout;
    PREQUESTED_FILE_ATTRIBUTES requestedFile;

    DBG_UNREFERENCED_PARAMETER(FilterExtension);

    NT_ASSERT(DiskByteOffset != NULL);
    NT_ASSERT(Mdl != NULL);

    //
    // If the user has completed the challenge, update the underlying 
    // dump MDL to write the key to the crash file.
    //
    if (g_Context->CtfStateInformation.CtfStageCompleted == ChallengeStage3)
    {
        requestedFile = &g_Context->StagingInformation.RequestedFileAttributes;
        layout = &requestedFile->Layout;

        //
        // Completion of stage 3 implies a staged patch operation with:
        //      1) a valid patch length
        //      2) valid disk runs for target patch file
        //
        NT_VERIFY(requestedFile->OverwriteLength > 0);
        NT_VERIFY(requestedFile->OverwriteLength <= MAX_PATCH_BYTE_COUNT);
        NT_VERIFY(layout->DiskRuns != NULL);
        
        //
        // Uncomment to append the CTF key to only a single MDL
        // destined for the dump.  Originally I thought this was
        // needed to decrease the likelihood of corrupting the dump,
        // until I realized not corrupting the dump is a harder 
        // problem which I am going to just avoid :)
        //
        //if (g_Context->CtfStateInformation.KeyDumped != FALSE)
        //{
        //    goto Exit;
        //}

        status = AppendKeyToDumpWriteMdl(DiskByteOffset, Mdl);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("DmpFlt: Failed to append key to MDL: %08x\n", status);
            goto Exit;
        }   
    }

Exit:

    //
    // Always force success status
    //

    status = STATUS_SUCCESS;

    return status;
}


/*!

    @brief The crash dump filter Dump_Read callback routine

    @details This function is called by crashdmp.sys for every read operation in
        the crash I/O path.  Filters are given the opportunity to do anything
        they want with the data buffer in the supplied MDL, which contains 
        data the OS just read from the dump or hiber file.  Typically a WDE
        driver will decrypt the contents.  Note that the in annotation for
        the DiskByteOffset and Mdl are wrong according to MSDN docs, which 
        states filters CAN modify these values.

    @param[in] FilterExtension - Pointer to our FILTER_EXTENSION structure

    @param[in] DiskByteOffset - The partition-relative offset of the target
        of this read operation.
      
    @param[in] Mdl - An MDL that describes and holds the contents of the data
        buffer which contains the data that was read from disk
        at the supplied DiskByteOffset.

    @return NTSTATUS code

*/
NTSTATUS
FltDumpRead (
    __in PFILTER_EXTENSION FilterExtension,
    __in PLARGE_INTEGER DiskByteOffset,
    __in PMDL Mdl
    )
{
    DBG_UNREFERENCED_PARAMETER(FilterExtension);
    DBG_UNREFERENCED_PARAMETER(DiskByteOffset); 
    DBG_UNREFERENCED_PARAMETER(Mdl);

    return STATUS_SUCCESS;
}

/*!

    @brief Enumerates crash dump filter drivers loaded in the crash path

    @details Debug function only

    @return N/A

*/
VOID
PrintFilters (
    VOID
    )
{
    PFILTER_CONTEXT context;
    PLIST_ENTRY entry, listHead;

    context = (PFILTER_CONTEXT)g_Context->InitializationData; 
    listHead = &context->Link;
    entry = listHead;

    do
    {       
        context = CONTAINING_RECORD(entry, FILTER_CONTEXT, Link);

        NT_ASSERT(context != NULL);

        DBGPRINT("DmpFlt: FILTER_CONTEXT at %p:\n", context);
        DBGPRINT("\tFilterInitializationData %p\n", &context->FilterInitData);
        DBGPRINT("\tFilterExtension %p\n", &context->FilterExtension);
        DBGPRINT("\tCommonContext %p\n", context->Context);
        DBGPRINT("\tUnknown %p\n", context->UnknownPointer);
        DBGPRINT("\tUnknown %08x\n", context->UnknownNumber);

        entry = entry->Blink;

    } while (entry != NULL && entry != listHead);
}

} // extern "C"