#pragma once

#ifndef VULN_INTEGER
#define VULN_INTEGER
#endif


#include "log.hpp"
#include "common.hpp"


namespace Vuln {
	class IntegerDowngrade {
	public:
		ERROR_T Execute(V_PARAS* args);

	private:
		void VulnFunc(uint32 size);
	};

	ERROR_T IntegerDowngrade::Execute(V_PARAS* args) {
		printf("integer downgrade execute...\n");

		uint32 size = 8;

		VulnFunc(size - 9);

		return 0x40000000 | 0xffff;
	}
	/*
	size be checked  with caller function!
	*/
	void IntegerDowngrade::VulnFunc(uint32 size) {
#ifdef SECURE
		if (size > 8) {
			size = size % 9;
		}
#else
		// nothing
#endif

		char data[8] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
		char* buf = (char*)LocalAlloc(0x40,8);
		__try
		{
			// stack overflow here
			memset(data, 0, size);
			dump_hex_top2("hex: ",data, ARRAYSIZE(data));
			hexdump2(data, ARRAYSIZE(data));
			// integer downgrade here
			memcpy(buf, data, size);
			dump_hex_top2("hex: ", buf, 8);
			hexdump2(buf, 8);
		}
		__except (EXCEPTION_ACCESS_VIOLATION)
		{
			EPrint("IntegerDowngrade trigger");
			EPrint("error code: %d", GetExceptionCode());
		}
		LocalFree(buf);
	}
}