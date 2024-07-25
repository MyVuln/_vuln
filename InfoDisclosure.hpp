#pragma once

#ifndef VULN_INFFORMATION_DISCLOSURE
#define VULN_INFFORMATION_DISCLOSURE
#endif


#include "log.hpp"
#include "common.hpp"
#include "IMemoryLeak.hpp"

namespace Vuln {
	class InfoDisclosure : public IMemoryLeak {
	public:
		ERROR_T Execute(V_PARAS* args) {
			printf("overflow read which results in information disclosure\n");

			assert(args != null);

			VulnFunc(args);

			return 0x40000000 | 0xfffe;
		}
	private:
		void VulnFunc(V_PARAS* args) {
#ifdef SECURE
			if (args->Count > 8) {
				args->Count = args->Count % 9;
			}
#else
			// nothing
#endif
			hexdump2((void*)((DWORD_PTR)args->Address + 64),args->Count);
		}
	};
}