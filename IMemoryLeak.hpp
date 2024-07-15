#pragma once

#ifndef VULN_MEMORY_LEAK
#define VULN_MEMORY_LEAK
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	enum MemoryLeakType {
		_InfoDisclosure,
		_ArbitraryRead
	};

	class IMemoryLeak
	{
	public:
		virtual ERROR_T Execute(V_PARAS* args) = 0;
		LPVOID Alloc(DWORD size) {
			return malloc(size);
		}
		ERROR_T SetType(MemoryLeakType type) {
			Type = type;
			return 0x0000;
		}
		ERROR_T Dispose(V_PARAS* args) {
			assert(args != null);
			free(args->Address);
			args->Address = null;
			args->Count = 0;
			return 0x00;
		}
	private:
		virtual void VulnFunc(V_PARAS* args) = 0;
	protected:
		MemoryLeakType Type;
	};
}