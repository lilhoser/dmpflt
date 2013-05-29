/*!
    ------------------------------------------------------------
    @file       Timer.hpp
    
    @brief      Timer library header
    
    @details    The Timer module handles all timed aspects of
                the driver's operations.

    @author     Aaron LeMasters
    ------------------------------------------------------------
*/
 
#ifndef __TIMER_HPP__
#define __TIMER_HPP__
#pragma once

#include <ntifs.h>
#include "Common.hpp"
#include "Dump.hpp"
#include "PreCrashStaging.hpp"

#define BSOD_INTERVAL 240
#define EXPOSE_LOGFILE_INTERVAL 10
#define STAGING_INTERVAL 15

#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000L))

extern "C" {

KSTART_ROUTINE TimerWait;

VOID
TimerWait (
    __in PVOID Argument
    );

VOID
InitializeTimers (
    VOID
    );

VOID
CancelTimers (
    VOID
    );

VOID
DoBugCheck (
    VOID
    );
}

#endif