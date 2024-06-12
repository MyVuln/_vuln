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
		LPVOID onlyreadAddr = LocalAlloc(LPTR,0x1000);
		EPrint("virtualalloc  read-only mem: 0x%x", onlyreadAddr)
#ifdef SECURE
			free(onlyreadAddr);
			onlyreadAddr = NULL;
			if (onlyreadAddr) {
				*onlyreadAddr = 0x10 | 0x0100;
			}
#else
			LocalFree(onlyreadAddr);
		VulnFunc((PBYTE)onlyreadAddr);
#endif
		DPrint("no use after free")
			return 0x40000001;
	}

	void UAF::VulnFunc(PBYTE addr) {
		// use after free
		*addr = 0x10 | 0x0100;
	}
}