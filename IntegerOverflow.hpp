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
		char data[8] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
		char* buf = (char*)LocalAlloc(0x40,8);
		try
		{
			// stack overflow here
			memset(data, 0, size);
			// integer downgrade here
			memcpy(buf, data, size);
		}
		catch (const char* msg)
		{
			EPrint("IntegerDowngrade trigger");
			EPrint(msg);
		}
		LocalFree(buf);
	}
}