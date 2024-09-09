#pragma once

#ifndef VULN_OOBR_NonZeroEnd
#define VULN_OOBR_NonZeroEnd
#endif


#include "log.hpp"
#include "common.hpp"

#define BUF_SIZE 0x10

namespace Vuln {
	/**
	* 
	* https://whereisk0shl.top/post/isolate-me-from-sandbox-explore-elevation-of-privilege-of-cng-key-isolation
	*/
	class NonZeroEnd
	{
	public:
		NonZeroEnd();
		~NonZeroEnd();
	public:
		ERROR_T Execute(V_PARAS* args);
	private:
		ERROR_T SetData(char* data, int size);
		ERROR_T GetData(char** data, int* outsize);
		PVOID Buf;
	private:
	};

	NonZeroEnd::NonZeroEnd()
	{
	}


	NonZeroEnd::~NonZeroEnd()
	{
		if (Buf) {
			free(Buf);
			Buf = NULL;
		}
	}

	ERROR_T NonZeroEnd::Execute(V_PARAS* args) {

		char* poc_data = (char*)VirtualAlloc(0,BUF_SIZE,MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		memset(poc_data, 0x41, BUF_SIZE);
		int size = strlen(poc_data);

		*(BYTE*)(DWORD_PTR)(poc_data + size) = 0x41;

		SetData(poc_data, size);
		VirtualFree(poc_data, BUF_SIZE,MEM_DECOMMIT | MEM_RELEASE);
#ifdef SECURE

#else
		char* buf = 0;
		int outsize = 0;
		GetData(&buf, &outsize);
		DPrint("information disclosure size: 0x%x %d", outsize,outsize);
		hexdump2(buf, outsize);
#endif
		return 0x40000001;
	}

	ERROR_T NonZeroEnd::SetData(char* data, int size) {
		Buf = malloc(size);
		DPrint("Buf mem addr: 0x%x",Buf)
		memcpy(Buf, data, size);
		return 0x00;
	}

	ERROR_T NonZeroEnd::GetData(char** data, int* outsize) {
		*outsize = strlen((char*)Buf);
		*data = (char*)malloc(*outsize);
		memcpy(*data, Buf, *outsize);
		return 0x00;
	}
}