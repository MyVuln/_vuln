#pragma once

#ifndef VULN_ARBITRARY
#define VULN_ARBITRARY
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	class ArbitraryIncrement
	{
	public:
		ArbitraryIncrement();
		~ArbitraryIncrement();
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(PBYTE addr);

	private:

	};

	ArbitraryIncrement::ArbitraryIncrement()
	{
	}

	ArbitraryIncrement::~ArbitraryIncrement()
	{
	}
	ERROR_T ArbitraryIncrement::Execute(V_PARAS* args) {
		LPVOID onlyreadAddr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
		EPrint("virtualalloc  read-only mem: 0x%x", onlyreadAddr)
#ifdef SECURE
			MEMORY_BASIC_INFORMATION mmb = { 0 };
			
		if (VirtualQuery(onlyreadAddr, &mmb, sizeof(MEMORY_BASIC_INFORMATION))) {
			if (mmb.AllocationProtect == (mmb.AllocationProtect | PAGE_READWRITE)) {
				VulnFunc((PBYTE)onlyreadAddr);
			}
			else
			{
				DPrint("BaseAddress: %p",mmb.AllocationBase)
				DPrint("AllocationBase: %p",mmb.AllocationBase)
				DPrint("AllocationProtect: %d",mmb.AllocationProtect)
				DPrint("Protect: %d",mmb.Protect)
				DPrint("Type: %d",mmb.Type)
			}
		}
		else
		{
			EPrint("error code: %d",GetLastError())
		}
#else
			VulnFunc((PBYTE)onlyreadAddr);
#endif

		VirtualFree(onlyreadAddr,0, MEM_RELEASE);
		DPrint("call virtual free succ")
		return 0x40000001;
	}

	void ArbitraryIncrement::VulnFunc(PBYTE addr) {

		(*(PCHAR)addr)++;
	}
}