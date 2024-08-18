#pragma once

#ifndef VULN_COMMON
#define VULN_COMMON
#endif

#include <Windows.h>
#include <stdio.h>
#include <assert.h>

typedef char gint8;
typedef unsigned char gchar;
typedef unsigned char guint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long uint64;

#define null 0

typedef unsigned int ERROR_T;

typedef struct V_PARAS {
	SIZE_T Count;
	PVOID Address;
}V_PARAS, * PV_PARAS;

namespace Vuln {
	/*
	.Common

	define hex dump and support functions
	*/

	class Common
	{
	public:
		Common();
		~Common();
		static void
			hex_byts(BYTE* buf, const char* str, int* psize);
		static void
			dump_hex(const char* head, const char* tail, const void* s, size_t len);
		static void
			dump_data(const char* head, const void* s, size_t len, FILE* f);
		static void
			dump_data2(const void* s, size_t len, FILE* f);

	private:

	};

	Common::Common()
	{
	}

	Common::~Common()
	{
	}
	void
		Common::hex_byts(BYTE* buf, const char* str, int* psize) {
		*psize = 0;
		if (strlen(str) == 0 || str == NULL) {
			return;
		}

		if (strlen(str) % 2 != 0) {
			/*
			odd number
			*/
			*psize = -1;
			return;
		}

		guint8 c;
		for (size_t i = 0; i < strlen(str) / 2; i++) {
			gchar v0 = str[i * 2];
			gint8 h0 = (v0 >= '0' && v0 <= '9') ? v0 - '0' : (v0 >= 'a' && v0 <= 'f') ? v0 - 'a' + 10 : (v0 >= 'A' && v0 <= 'F') ? v0 - 'A' + 10 : -1;
			gchar v1 = str[i * 2 + 1];
			gint8 h1 = (v1 >= '0' && v1 <= '9') ? v1 - '0' : (v1 >= 'a' && v1 <= 'f') ? v1 - 'a' + 10 : (v1 >= 'A' && v1 <= 'F') ? v1 - 'A' + 10 : -1;

			if (h0 == -1 || h1 == -1) {
				*psize = -2;
				return;
			}

			c = (h0 << 4) | h1;
			buf[i] = c;
		}
		*psize = strlen(str) / 2;
	}

	void
		Common::dump_hex(const char* head, const char* tail, const void* s, size_t len) {
		printf("%s", head);
		for (size_t i = 0; i < len; i++)
		{
			printf("%02x", ((BYTE*)s)[i]);
		}
		printf("%s", tail);
	}

	void
		Common::dump_data(const char* head, const void* s, size_t len, FILE* f){
		if (head != null)
			fprintf(f, "%s\n", head);
		size_t i, j;
		const u_char* p = (const u_char*)s;

		for (i = 0; i < len; i += 16) {
			fprintf(f, "%.4zu: ", i);
			for (j = i; j < i + 16; j++) {
				if (j < len)
					fprintf(f, "%02x ", p[j]);
				else
					fprintf(f, "   ");
			}
			fprintf(f, " ");
			for (j = i; j < i + 16; j++) {
				if (j < len) {
					if (isascii(p[j]) && isprint(p[j]))
						fprintf(f, "%c", p[j]);
					else
						fprintf(f, ".");
				}
			}
			fprintf(f, "\n");
		}
	}

	void
		Common::dump_data2(const void* s, size_t len, FILE* f) {
		dump_data(null, s, len, f);
	}


	class VulnBase
	{
	public:
		VulnBase();
		~VulnBase();

	private:

	};


#define hexdump(h,s,len) Common::dump_data(h,s,len,stdout)
#define hexdump2(s,len) Common::dump_data2(s,len,stdout)

#define dump_hex_top(s,len) Common::dump_hex("","\n",s,len)
#define dump_hex_top2(h,s,len) Common::dump_hex(h,"\n",s,len)

#define EPrint(...) printf("[-] "); printf(__VA_ARGS__); printf("\n");
#define DPrint(...) printf("[+] "); printf(__VA_ARGS__); printf("\n");
#define IPrint(...) printf("[*] "); printf(__VA_ARGS__); printf("\n");

#define DebugPrint(...)	DPrint("%s %d lines\n", __FUNCTION__, __LINE__);

#pragma warning(disable:4789)

#define SendVuln(x)\
	x* tmp_##x = new x();\
	tmp_##x->Execute(NULL);\
	delete tmp_##x;
}