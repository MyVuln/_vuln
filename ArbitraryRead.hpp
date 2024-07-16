#pragma once

#ifndef VULN_ARBITRARYREAD
#define VULN_ARBITRARYREAD
#endif


#include "log.hpp"
#include "common.hpp"
#include "IMemoryLeak.hpp"

#define ThreadQuerySetWin32StartAddress 9
typedef NTSTATUS(WINAPI* pNtQIT)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef ULONG (WINAPI* pRtlNtStatusToDosError)(NTSTATUS Status);

/// <summary>
/// https://github.com/WizardVan/ThreadStartAddress/blob/master/main.c
/// </summary>
/// <param name="hThread"></param>
/// <returns>the specified thread start address</returns>
LPVOID WINAPI GetThreadStartAddress(HANDLE hThread)
{
	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	ULONGLONG dwStartAddress;

	pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

	if (NtQueryInformationThread == NULL)
		return 0;

	HANDLE hCurrentProcess = GetCurrentProcess();
	if (!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {
		SetLastError(ERROR_ACCESS_DENIED);

		return 0;
	}

	ntStatus = NtQueryInformationThread(hDupHandle, (THREAD_INFORMATION_CLASS)ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(ULONGLONG), NULL);
	CloseHandle(hDupHandle);
	pRtlNtStatusToDosError RtlNtStatusToDosError = (pRtlNtStatusToDosError)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlNtStatusToDosError");
	if (ntStatus != 0) {
		printf("error code %d\n", RtlNtStatusToDosError(ntStatus));
		return 0;
	}
	return (LPVOID)dwStartAddress;

}

LPVOID GetHeapChunkAddress() {
	HANDLE hHeap = GetProcessHeap();
    PROCESS_HEAP_ENTRY Entry;
	if (HeapLock(hHeap)) {

	}

    Entry.lpData = NULL;
    while (HeapWalk(hHeap, &Entry) != FALSE) {
        if ((Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            wprintf(TEXT("Allocated block"));

            if ((Entry.wFlags & PROCESS_HEAP_ENTRY_MOVEABLE) != 0) {
				wprintf(TEXT(", movable with HANDLE %#p"), Entry.Block.hMem);
            }

            if ((Entry.wFlags & PROCESS_HEAP_ENTRY_DDESHARE) != 0) {
				wprintf(TEXT(", DDESHARE"));
            }
        }
        else if ((Entry.wFlags & PROCESS_HEAP_REGION) != 0) {
			wprintf(TEXT("Region\n  %d bytes committed\n") \
                TEXT("  %d bytes uncommitted\n  First block address: %#p\n") \
                TEXT("  Last block address: %#p\n"),
                Entry.Region.dwCommittedSize,
                Entry.Region.dwUnCommittedSize,
                Entry.Region.lpFirstBlock,
                Entry.Region.lpLastBlock);
        }
        else if ((Entry.wFlags & PROCESS_HEAP_UNCOMMITTED_RANGE) != 0) {
			wprintf(TEXT("Uncommitted range\n"));
        }
        else {
			wprintf(TEXT("Block\n"));
        }

		wprintf(TEXT("  Data portion begins at: %#p\n  Size: %d bytes\n") \
            TEXT("  Overhead: %d bytes\n  Region index: %d\n\n"),
            Entry.lpData,
            Entry.cbData,
            Entry.cbOverhead,
            Entry.iRegionIndex);
		return Entry.lpData;
    }

    //
    // Unlock the heap to allow other threads to access the heap after 
    // enumeration has completed.
    //
    if (HeapUnlock(hHeap) == FALSE) {
    }

	return 0;
}

namespace Vuln {
#define AR_SELF_ALLOC						0
#define AR_HEAP_ADDR						1
#define AR_THREAD_START_ADDR				2
#define AR_MODULE_PE_ADDR					3
	typedef struct _MemCallback
	{
		BOOL HasInit;
		LPVOID(*ThreadStartAddr)(HANDLE hThread);
		LPVOID(*HeapChunkAddr)();
	}MemCallback, * PMemCallback;

	class ArbitraryRead : public IMemoryLeak {
	public:
		ERROR_T Execute(V_PARAS* args) {
			printf("arbitrary read with the specified address and size which all them be controlled by input\n");
			printf("%x %d\n", args->Address, args->Count);
			assert(args != null);

			VulnFunc(args);

			printf("normal finished\n");
			return 0x40000000 | 0xfffd;
		}
	private:
		void VulnFunc(V_PARAS* args) {
#ifdef SECURE
			// no check
#else
			// nothing
#endif
			__try
			{
				hexdump2(args->Address, args->Count);
			}
			__except (1)
			{
				DPrint("address %x was invalid with size: %d\n", args->Address, args->Count);
			}
		}

		void RegisterMemCallback() {
			callback = (MemCallback*)malloc(sizeof(MemCallback));
			callback->HasInit = TRUE;
			callback->ThreadStartAddr = GetThreadStartAddress;
			callback->HeapChunkAddr = GetHeapChunkAddress;
		}
		MemCallback* callback;
	public:
		PVOID GetMemAddress(USHORT type,LPVOID param) {
			if (callback == NULL || callback->HasInit == FALSE) {
				RegisterMemCallback();
			}

			switch (type)
			{
			case 0:
				return param;
			case 1:
				// enum heap chunk
				return callback->HeapChunkAddr();
			case 2:
				return callback->ThreadStartAddr(GetCurrentThread());
				// thread addr
			case 3:
				// pe addr
				return GetModuleHandleA(NULL);
			default:
				break;
			}
		}
	};
}