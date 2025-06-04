#pragma once

#ifndef VULN_TYPECOMFUSION
#define VULN_TYPECOMFUSION
#endif


#include "log.hpp"
#include "common.hpp"

namespace Vuln {
	/// <summary>
	/// read VT_LPSTR the memory,
	/// but Data is not char*, it got a integer value from the external sight
	/// </summary>
	typedef struct _comfustion {
		VARENUM Type;
		char* Data;
	}comfustion;

	/// <summary>
	/// https://www.usenix.org/conference/usenixsecurity23/presentation/zhang-yuxing
	/// COMFusion
	/// </summary>
	class COMFusion {
	public:
		COMFusion();
		~COMFusion();
	public:
		ERROR_T Execute(V_PARAS* args);
	};

	COMFusion::COMFusion() {

	}

	COMFusion::~COMFusion() {

	}

	ERROR_T COMFusion::Execute(V_PARAS* args) {
		char buf[0x40];
		comfustion* cf = (comfustion*)malloc(sizeof(comfustion));
		if (cf == NULL) {
#ifdef DEBUGLOG
			DPrint("memory not enough\n");
#endif
			return 0x87;
		}
		memset(buf, 0, 0x40);
		memset(cf, 0, sizeof(comfustion));
		cf->Type = VT_LPSTR;
		cf->Data = (char*) args->Count;
		if (cf->Data == NULL) {
#ifdef DEBUGLOG
			DPrint("input value is not valid\n");
			return 0xc6;
#endif
		}
		memcpy(buf, cf->Data, 0x40);
		hexdump2(buf, 0x40);

#ifdef DEBUGLOG
		DPrint("%p\n", cf->Data);
#endif
		if (cf) {
			free(cf);
		}
		return 0;
	}
}