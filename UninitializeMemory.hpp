#pragma once
#pragma once

#ifndef VULN_UNINITIALIZE_MEMORY
#define VULN_UNINITIALIZE_MEMORY
#endif

#pragma once
#include "log.hpp"
#include "common.hpp"

#define CONTROL_DATA 0x42
#define ALLOC_SIZE 0x80

namespace Vuln {
	class UninitializeMemory
	{
	public:
		UninitializeMemory();
		~UninitializeMemory();
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(PBYTE addr);
		void controller_heap_memory();

	private:

	};

	UninitializeMemory::UninitializeMemory()
	{
	}

	UninitializeMemory::~UninitializeMemory()
	{
	}

	void UninitializeMemory::controller_heap_memory() {
		char* buffer = (char*)malloc(ALLOC_SIZE);
		for (size_t i = 0; i < ALLOC_SIZE; i++)
		{
			*buffer = CONTROL_DATA;
			buffer++;
		}
		buffer = (char*)((DWORD_PTR)buffer - ALLOC_SIZE);
		hexdump("init heap memory", buffer, ALLOC_SIZE);
		if (buffer) {
			free(buffer);
			buffer = NULL;
		}
	}

	ERROR_T UninitializeMemory::Execute(V_PARAS* args) {
		controller_heap_memory();
		VulnFunc(NULL);
		int num = -4;
		DebugPrint()
#ifdef SECURE
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
		DebugPrint()
			return 0x40000001;
	}

	void UninitializeMemory::VulnFunc(PBYTE addr) {
		/*
			https://www.blackhat.com/docs/eu-15/materials/eu-15-Chen-Hey-Man-Have-You-Forgotten-To-Initialize-Your-Memory-wp.pdf
			https://www.blackhat.com/docs/eu-15/materials/eu-15-Chen-Hey-Man-Have-You-Forgotten-To-Initialize-Your-Memory.pdf
		*/

		/*
		uninitialize stack memeory
		*/
#ifdef UNINIT_STACK
		int num;
		short num2;
		unsigned num3;
		char stackm[24];
		printf("%d\n", num);
		printf("%d\n", num2);
		printf("%d\n", num3);
		hexdump2(stackm, 24);
#endif
		/*
		use before initialize  (UBI)
		init heap memory
		0000: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		0016: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		0032: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		0048: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		leak heap memory
		0000: e0 1f 89 f6 45 01 00 00 50 01 88 f6 45 01 00 00  ....E...P...E...
		0016: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		0032: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		0048: 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42  BBBBBBBBBBBBBBBB
		leak first addr
		0000: 50 01 88 f6 45 01 00 00 60 ff 88 f6 45 01 00 00  P...E...`...E...
		0016: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		0032: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		0048: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		leak second addr
		0000: 50 01 88 f6 45 01 00 00 60 ff 88 f6 45 01 00 00  P...E...`...E...
		0016: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
		0032: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

		*/
		char *heapm = (char*)malloc(64);
		hexdump("leak heap memory", heapm, 0x50);

		hexdump("leak first addr", (void*)*(ULONGLONG*)heapm,64);
		hexdump("leak second addr", (void*)*((ULONGLONG*)heapm++),64);
	}
}