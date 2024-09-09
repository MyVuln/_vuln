#pragma once

#ifndef VULN_OOBR_NonZeroEnd
#define VULN_OOBR_NonZeroEnd
#endif


#include "log.hpp"
#include "common.hpp"

#define BUF_SIZE 0x10

int memsetw(wchar_t* buf, unsigned int val, unsigned int size) {
	if (val > 0xff) {
		return 0x01;
	}
	if (buf == NULL || (DWORD_PTR)buf < 0x1000) {
		return 0x02;
	}

	for (size_t i = 0; i < size; i++)
	{
		buf[i] = val;
	}
	buf[size] = 0x00;

	unsigned int buf_size = 0;
	do
	{
		buf_size++;
	} while (*(WORD*)((DWORD_PTR)buf + 2 * buf_size) != 0);

	if (buf_size == size) {
		return 0x00;
	}
	memset(buf, 0, size);
	return 0x04;
}


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
		ERROR_T SetData(wchar_t* data, int size);
		ERROR_T GetData(wchar_t** data, int* outsize);
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

		wchar_t* poc_data = (wchar_t*)malloc(BUF_SIZE);
		if (memsetw(poc_data, 0x41, BUF_SIZE)) {
			DPrint("memsetw failed \n");
			return 0xffffeeee;
		}

		int size = lstrlenW(poc_data);


		*(WORD*)((DWORD_PTR)poc_data + BUF_SIZE * 2) = 0x43;

		SetData(poc_data, size);
		free(poc_data);
#ifdef SECURE

#else
		wchar_t* buf = 0;
		int outsize = 0;
		GetData(&buf, &outsize);
		DPrint("information disclosure size: 0x%x %d", outsize,outsize);
		hexdump2(buf, outsize);
#endif
		return 0x40000001;
	}

	ERROR_T NonZeroEnd::SetData(wchar_t* data, int size) {
		Buf = malloc(size);
		DPrint("Buf mem addr: 0x%x",Buf)
		memcpy(Buf, data, size);
		return 0x00;
	}

	ERROR_T NonZeroEnd::GetData(wchar_t** data, int* outsize) {
		*outsize = lstrlenW((wchar_t*)Buf);
		*data = (wchar_t*)malloc(*outsize);
		memcpy(*data, Buf, *outsize);
		return 0x00;
	}
}