#pragma once

#ifndef VULN_DOUBLE_FETCH
#define VULN_DOUBLE_FETCH
#endif


#include "log.hpp"
#include "common.hpp"

PBYTE g_double_fetch_target;

namespace Vuln {
	/**
	* What is DoubleFetch?
	* https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/race/double-fetch/
	* https://research.qianxin.com/archives/1355
	*/
	class DoubleFetch
	{
	public:
		DoubleFetch();
		~DoubleFetch();
	public:
		ERROR_T Execute(V_PARAS* args);
	private:
		void VulnFunc();
	private:
	};



	DWORD WINAPI ThreadProc(LPVOID lpParameter);


	DoubleFetch::DoubleFetch()
	{
	}


	DoubleFetch::~DoubleFetch()
	{
	}

	static DWORD WINAPI ThreadProc(LPVOID lpParameter) {
		while ((DWORD_PTR)g_double_fetch_target > 0x1000)
		{
			Sleep(500);
			g_double_fetch_target =(PBYTE)0x0002;
			printf("g_double_fectch_target %x\n", g_double_fetch_target);
		}

		return 1;
	}

	ERROR_T DoubleFetch::Execute(V_PARAS* args) {
		g_double_fetch_target = (PBYTE)malloc(0x1000);
		EPrint("virtualalloc  read-only mem: 0x%x", g_double_fetch_target)
#ifdef SECURE

#else
		HANDLE handle = CreateThread(0, 0, ThreadProc, this, 0, 0);
		CloseHandle(handle);
		VulnFunc();
#endif
		DPrint("no double fetch")
			return 0x40000001;
	}

	void DoubleFetch::VulnFunc() {
		// 1. double fetch firstly check parameters
		if ((DWORD_PTR)g_double_fetch_target > 0x1000) {

			printf("1 g_double_fectch_target check passed %x\n", g_double_fetch_target);


			// make an enough time for changing-thread
			Sleep(1000);

			printf("2 g_double_fectch_target check passed %x\n", g_double_fetch_target);

			// 2. race condition successfully. this example will crash as free an invalid address
			free(g_double_fetch_target);
		}
	}
}