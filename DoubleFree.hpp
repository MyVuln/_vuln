#pragma once

#ifndef VULN_DOUBLEFREE
#define VULN_DOUBLEFREE
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	class DoubleFree
	{
	public:
		DoubleFree();
		~DoubleFree();
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(PBYTE addr);

	private:

	};

	DoubleFree::DoubleFree()
	{
	}

	DoubleFree::~DoubleFree()
	{
	}
	ERROR_T DoubleFree::Execute(V_PARAS* args) {
		LPVOID onlyreadAddr = malloc(0x1000);
		EPrint("virtualalloc  read-only mem: 0x%x", onlyreadAddr)
#ifdef SECURE
			if (onlyreadAddr) {
				free(onlyreadAddr);
				onlyreadAddr = NULL;
			}
#else
			free(onlyreadAddr);
		VulnFunc((PBYTE)onlyreadAddr);
#endif
		DPrint("no double free succ")
			return 0x40000001;
	}

	void DoubleFree::VulnFunc(PBYTE addr) {

		free(addr);
	}
}