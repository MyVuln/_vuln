#pragma once

#ifndef VULN_UAF
#define VULN_UAF
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	namespace UseAfterFree {
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
				*(PBYTE)onlyreadAddr = 0x10 | 0x0100;
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

#pragma region MS_T120_UAF


		/// <summary>
		/// RDP BlueKeep  MS_T120 Static Virtual Channel  MS_T120 UAF
		/// </summary>
		class MS_T120_UAF {
		public:
			MS_T120_UAF();
			~MS_T120_UAF();
		public:
			ERROR_T Execute(V_PARAS* args);

			PVOID ChannelTable[0x20];

			BOOL SecureCheck;

		private:
			void VulnFunc(PBYTE addr);

		private:
		};

		MS_T120_UAF::MS_T120_UAF() {
			ChannelTable[0x1e] = LocalAlloc(LPTR, 0x1000);
			DPrint("alloc 0x1e addr: %p by default", ChannelTable[0x1e])
		}
		MS_T120_UAF::~MS_T120_UAF() {

		}

		ERROR_T MS_T120_UAF::Execute(V_PARAS* args) {
			// 1. alloc index 0x02 address when 0x1e was null
			if (ChannelTable[0x1e] == NULL) {
				ChannelTable[0x02] = LocalAlloc(LPTR, 0x1000);
				DPrint("alloc 0x02 addr: %p", ChannelTable[0x02])
			}
			else
			{
				ChannelTable[0x02] = ChannelTable[0x1e];
				DPrint("cache 0x02 addr: %p by default", ChannelTable[0x02])
					SecureCheck = true;
			}
			// 2.free 0x02
			if (LocalFree(ChannelTable[0x02]) == NULL) {
				DPrint("free %p successfully", ChannelTable[0x02])
#ifdef SECURE
					if (SecureCheck) {
						ChannelTable[0x02] = NULL;
						ChannelTable[0x1e] = NULL;
					}
#endif
			}

			// 3. trigger vuln that use 0x1e pointer (dangling pointer)
			VulnFunc((BYTE*)ChannelTable[0x1e]);

			DPrint("never crash")

				return 0x00;
		}

		void MS_T120_UAF::VulnFunc(PBYTE addr) {
			if (addr)
				*(PBYTE)*addr = 0x41;
		}

#pragma endregion


#pragma region Exploitation_UAF
		/*
		Long time ago, came across @k0shl https://whereisk0shl.top/post/a-trick-the-story-of-cve-2024-26230
		windows telephone service uaf in user mode and k0shl finished the exploitation because of full control on chance of releasing and using object
		under the premise of exploitation, it seems like c++ vftable pointer hijacking thereby got a chance to local aribitrary code execution.
		Meanwhile, I managed to design an explotitable uaf code base, so we arriave here!
		*/

		typedef struct _uaf_context {

		}uaf_context, * puaf_context;

		class Exp_UAF
		{
		public:
			Exp_UAF();
			~Exp_UAF();
		public:
			ERROR_T Execute(V_PARAS* args);

		private:
			void VulnFunc(PBYTE addr);
		};

		Exp_UAF::Exp_UAF()
		{
		}

		Exp_UAF::~Exp_UAF()
		{
		}

		ERROR_T Exp_UAF::Execute(V_PARAS* args) {
			return 0x3000041;
		}

		void Exp_UAF::VulnFunc(PBYTE addr) {

		}
#pragma endregion
	}
}