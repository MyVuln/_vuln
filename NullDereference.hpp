#pragma once

#ifndef VULN_NULL_DEREFERENCE
#define VULN_NULL_DEREFERENCE
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	class NullDereference
	{
	public:
		NullDereference();
		~NullDereference();
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(PBYTE addr);

	private:

	};

	NullDereference::NullDereference()
	{
	}

	NullDereference::~NullDereference()
	{
	}
	ERROR_T NullDereference::Execute(V_PARAS* args) {
		int num = -4;
		DPrint("null pointer dereference")
#ifdef SECURE
			if (num != -4) {
				num = *(int*)(num + 4);
			}
			else
			{
				num = *(int*)(num + 4);
			}
#else
			__try
			{
				num = *(int*)(num + 4);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DPrint("exception has triggered")
			}
#endif
		DPrint("no null pointer dereference")
			return 0x40000001;
	}

	void NullDereference::VulnFunc(PBYTE addr) {
		int num = *addr;
	}
}