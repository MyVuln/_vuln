#pragma once

#ifndef VULN_UAF
#define VULN_UAF
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	class UAF
	{
	public:
		UAF();
		~UAF();
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(PBYTE addr);

	private:

	};

	UAF::UAF()
	{
	}

	UAF::~UAF()
	{
	}
	ERROR_T UAF::Execute(V_PARAS* args) {
		LPVOID onlyreadAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
		EPrint("virtualalloc  read-only mem: 0x%x", onlyreadAddr)
#ifdef SECURE
			if (VirtualFree(onlyreadAddr, 0, MEM_RELEASE)) {
				onlyreadAddr = NULL;
			}
			if (onlyreadAddr) {
				*onlyreadAddr = 0x10 | 0x0100;
			}
#else
			/*
			localfree
			If the process tries to examine or modify the memory after it has been freed, 
			heap corruption may occur or an access violation exception (EXCEPTION_ACCESS_VIOLATION) may be generated.

			*/
		if (VirtualFree(onlyreadAddr, 0, MEM_RELEASE)) {
			VulnFunc((PBYTE)onlyreadAddr);
		}
#endif
		DPrint("no use after free")
			return 0x40000001;
	}

	void UAF::VulnFunc(PBYTE addr) {
		DPrint("uaf start")
			// use after free
			char tmp[0x1000];
		RtlCopyMemory(addr, tmp, strlen(tmp));

		DPrint("uaf end")
	}
}