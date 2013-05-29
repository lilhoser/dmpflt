/*!
    ------------------------------------------------------------
    @file       Timer.cpp
    
    @brief      Timer library implementation
    
    @details    The Timer module handles all timed aspects of
                the driver's operations.

    @author     Aaron LeMasters
    ------------------------------------------------------------
 */

#include "Timer.hpp"

extern "C" {

//
// Pointer to our global context structure
//
extern PDMPFLT_CONTEXT g_Context;

//
// Set to TRUE in debugger to neuter bsod timer
//
#ifdef DBG
static BOOLEAN g_DebugDisableBsod = FALSE;
#endif

/*!

    @brief Initializes and sets all required timers.

    @return N/A

*/
VOID
InitializeTimers (
    VOID
    )
{
    LARGE_INTEGER timeout;      

    //
    // Expose the dump stack log file timer
    //
    timeout.QuadPart = RELATIVE(SECONDS(EXPOSE_LOGFILE_INTERVAL));
    KeInitializeTimerEx(&g_Context->TimerInformation.TimerExposeLogFile, 
                        SynchronizationTimer);
    KeSetTimerEx(&g_Context->TimerInformation.TimerExposeLogFile,
                 timeout, 
                 EXPOSE_LOGFILE_INTERVAL * 1000, 
                 NULL);

    //
    // Stage file copy (crash i/o path read) or file patch (crash i/o write)
    //
    timeout.QuadPart = RELATIVE(SECONDS(STAGING_INTERVAL));
    KeInitializeTimerEx(&g_Context->TimerInformation.TimerStageFile, 
                        SynchronizationTimer);
    KeSetTimerEx(&g_Context->TimerInformation.TimerStageFile,
                 timeout, 
                 STAGING_INTERVAL * 1000, 
                 NULL);

    //
    // BSOD
    //
    timeout.QuadPart = RELATIVE(SECONDS(BSOD_INTERVAL));
    KeInitializeTimerEx(&g_Context->TimerInformation.TimerBsod, 
                        SynchronizationTimer);
    KeSetTimerEx(&g_Context->TimerInformation.TimerBsod,
                 timeout, 
                 BSOD_INTERVAL * 1000, 
                 NULL);

    g_Context->TimerInformation.TimerSet = TRUE;

    return;
}

/*!

    @brief Cancels all timers.

    @return N/A

*/
VOID
CancelTimers (
    VOID
    )
{
    KeCancelTimer(&g_Context->TimerInformation.TimerExposeLogFile);
    KeCancelTimer(&g_Context->TimerInformation.TimerStageFile);
    KeCancelTimer(&g_Context->TimerInformation.TimerBsod);
}

/*!

    @brief The entry point for the timer thread created in DriverEntry.
           Primary dispatch point for control operations.

    @param[in] Argument - Unused 

    @return N/A

*/
VOID
TimerWait (
    __in PVOID Argument
    )
{
    PVOID objects[4];
    NTSTATUS status;
    PKWAIT_BLOCK waitBlocks;

    DBG_UNREFERENCED_PARAMETER(Argument);

    objects[0] = &g_Context->TimerInformation.TimerExposeLogFile;
    objects[1] = &g_Context->TimerInformation.TimerStageFile;
    objects[2] = &g_Context->TimerInformation.StopTimer;
    objects[3] = &g_Context->TimerInformation.TimerBsod;

    waitBlocks = (PKWAIT_BLOCK)ExAllocatePoolWithTag(NonPagedPool, 
                                                     sizeof(KWAIT_BLOCK)*ARRAYSIZE(objects),
                                                     DMPFLT_TAG);

    if (waitBlocks == NULL)
    {
        DBGPRINT("DmpFlt: Failed to allocate wait blocks.\n");
        goto Exit;
    }

    for ( ; ; )
    {
        status = KeWaitForMultipleObjects(ARRAYSIZE(objects),
                                          (PVOID*)&objects,
                                          WaitAny, 
                                          Executive,
                                          KernelMode,
                                          TRUE,
                                          NULL,
                                          waitBlocks);

        switch(status)
        {
            //
            // Expose the log file - we do this one time if successful
            //
            case STATUS_WAIT_0:
            {
                if (g_Context->StagingInformation.LogFileExposed == FALSE)
                {
                    status = ExposeDumpStackLogFile();

                    //
                    // Successfully enabling the dump stack log 
                    // allows us to expose it, thus completing stage 1.
                    //
                    if (NT_SUCCESS(status))
                    {
                        g_Context->CtfStateInformation.CtfStageCompleted = ChallengeStage1;
                    }
                }

                break;  
            }
            //
            // Attempt to stage a file patch or copy operation
            //
            case STATUS_WAIT_1:
            {
                //
                // Stage 1 must be completed before considering Stage 2 or 3.
                //
                if (g_Context->StagingInformation.LogFileExposed == FALSE)
                {
                    break;
                }

                //
                // Attempt to stage a file patch.
                // This always supercedes a read staging.
                //
                status = StageFilePatch();

                if (NT_SUCCESS(status))
                {
                    //
                    // Successfully staging a valid file for write completes stage 3
                    // and the challenge (even though the patch won't be carried out
                    // until next BSOD)
                    //
                    g_Context->CtfStateInformation.CtfStageCompleted = ChallengeStage3;

                    //
                    // Disable our driver by simply renaming it on disk.
                    //
                    status = DisableDriver();

                    if (!NT_SUCCESS(status))
                    {
                        DBGPRINT("DmpFlt: Failed to disable driver: %08x\n", status);
                    }                 

                    DoBugCheck();
                }

                //
                // If the patch failed or was not requested, attempt a copy operation.
                //
                if (!NT_SUCCESS(status) || 
                    g_Context->StagingInformation.StagedOperation != OperationPatch)
                {
                    status = StageFileCopy();

                    //
                    // Successfully staging a valid file for read does not 
                    // necessarily advance them to stage 3.  They need to
                    // have requested key.txt
                    //
                    if (NT_SUCCESS(status))
                    {
                        if (g_Context->CtfStateInformation.KeyFileRequested != FALSE)
                        {
                            g_Context->CtfStateInformation.CtfStageCompleted = ChallengeStage2;
                        }

                        DoBugCheck();
                    }
                }                

                break;
            }
            //
            // Stop waiting and kill this thread - only issued from
            // within our Cleanup function which is only called in
            // FltDumpUnload.
            //
            case STATUS_WAIT_2:
            {
                KeClearEvent(&g_Context->TimerInformation.StopTimer);
                goto Exit;
            }
            //
            // Bug check timer tick - do a BSOD!
            //
            case STATUS_WAIT_3:
            {
                DoBugCheck(); // doesn't return
                break;
            }
            default:
            {
                break;
            }
        }
    }

Exit:

    if (waitBlocks != NULL)
    {
        ExFreePoolWithTag(waitBlocks, DMPFLT_TAG);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*!

    @brief Deliberately bugchecks the system as part of CTF.

    @return N/A

*/
VOID
DoBugCheck (
    VOID
    )
{  
    //
    // @TODO:  Since there's a bug in this code path somewhere, 
    // the only way we can write to the screen is through the
    // bugcheck parameters.  The bug only manifests itself in 
    // stage 1 of the challenge (ie, dump stack logging is 
    // disabled).
    //
    if (g_Context->CtfStateInformation.CtfStageCompleted == ChallengeBegin)
    {
        g_BugCheckCode = 0x64756d70;
        g_BugCheckParam1 = 0x73746163;
        g_BugCheckParam2 = 0x6b2e6c6f;
        g_BugCheckParam3 = 0x672e746d;
        g_BugCheckParam4 = 0x70000000;
    }

#ifdef DBG
    DbgBreakPoint();

    if (g_DebugDisableBsod == FALSE)
    {
#endif
#pragma prefast(suppress: 28159, "Lolz I want to bugcheck!")
        KeBugCheckEx(g_BugCheckCode,
                     g_BugCheckParam1,
                     g_BugCheckParam2,
                     g_BugCheckParam3,
                     g_BugCheckParam4);
#ifdef DBG
    }
#endif
}

} // extern "C"