#pragma once

#ifndef VULN_NumbericTrancation
#define VULN_NumbericTrancation
#endif


#include "log.hpp"
#include "common.hpp"

#define FLAG_NumbericTrancation			0x0001
#define FLAG_NumbericTrancation			0x0002

#define INTEGER_OVERFLOW_VERSION_1		1

namespace Vuln {
	namespace IntegerOverflow {
		/*
		https://v-v.space/2024/08/23/CVE-2024-29050/
		crypt32!ASN1Dec_CRLDistributionPoints
		*/
		class NumbericTrancation {
		public:
			ERROR_T Execute(V_PARAS* args);

			NumbericTrancation();
			~NumbericTrancation();

		private:
			PVOID AllocMem(UINT16 size);
			BOOL FreeMem(PVOID addr);
		};

		NumbericTrancation::NumbericTrancation(){}
		NumbericTrancation::~NumbericTrancation() {}
		ERROR_T NumbericTrancation::Execute(V_PARAS* args) {
			// AllocMem  args type ushort  numberic trancation
			PVOID addr = AllocMem(args->Count);
			if (addr) {
				RtlCopyMemory(addr, args->Address, args->Count);
			}

			if (addr) {
				FreeMem(addr);
			}
			return 0x41000000;
		}

		PVOID NumbericTrancation::AllocMem(UINT16 size) {
			UINT16 _size = size;
			void* addr = malloc(_size);
			return addr;
		}

		BOOL NumbericTrancation::FreeMem(PVOID addr) {
			free(addr);
			return TRUE;
		}
	}
}