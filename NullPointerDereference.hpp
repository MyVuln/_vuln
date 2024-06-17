#pragma once

#ifndef VULN_NULL_POINTER_DEREFERENCE
#define VULN_NULL_POINTER_DEREFERENCE
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	class NullPointerDereference
	{
	public:
		NullPointerDereference();
		~NullPointerDereference();
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(PBYTE addr);

	private:

	};

	NullPointerDereference::NullPointerDereference()
	{
	}

	NullPointerDereference::~NullPointerDereference()
	{
	}
	ERROR_T NullPointerDereference::Execute(V_PARAS* args) {
		VulnFunc(NULL);
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

	void NullPointerDereference::VulnFunc(PBYTE addr) {
		/*
		https://j00ru.vexillium.org/2018/07/exploiting-a-windows-10-pagedpool-off-by-one/
		https://www.alex-ionescu.com/kernel-heap-spraying-like-its-2015-swimming-in-the-big-kids-pool/
		*/
		LPVOID addr2 = VirtualAlloc((LPVOID)0x0000056c00000558, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		RtlFillMemory((LPVOID)0x0000056c00000558, 16, 0x41);
		printf("%x\n",addr2);
	}
}