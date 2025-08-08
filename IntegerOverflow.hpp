#pragma once

#ifndef VULN_INTEGER
#define VULN_INTEGER
#endif


#include "log.hpp"
#include "common.hpp"

#define FLAG_INTEGER_OVERFLOW			0x0001
#define FLAG_USHORT_OVERFLOW			0x0002

#define INTEGER_OVERFLOW_VERSION_1		1

namespace Vuln {
	namespace IntegerOverflow {
		typedef struct _UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} UNICODE_STRING, * PUNICODE_STRING;

		typedef NTSTATUS(*fnRtlAppendUnicodeToString)(PUNICODE_STRING Destination, PCWSTR Source);
		typedef void(*ExecuteInvoke)(PVOID);

		typedef struct _IntegerOverflowSubCallback {
			USHORT Flag;
			ExecuteInvoke Execute;
		}IntegerOverflowSubCallback, * PIntegerOverflowSubCallback;

		typedef struct _IntegerOverflowContext {
			USHORT OverflowVersion;
			IntegerOverflowSubCallback Tables[];
		}IntegerOverflowContext, * PIntegerOverflowContext;

		class IntegerDowngrade {
		public:
			ERROR_T Execute(V_PARAS* args);

			IntegerDowngrade();
			~IntegerDowngrade();

			IntegerOverflowContext* pctx;

		private:
			void VulnFunc(uint32 size);
			void AppendUnicode(wchar_t* source);
		};

		IntegerDowngrade::IntegerDowngrade() {
			pctx = (IntegerOverflowContext*)malloc(sizeof(IntegerOverflowContext));
			pctx->OverflowVersion = INTEGER_OVERFLOW_VERSION_1;
			pctx->Tables[0].Flag = FLAG_INTEGER_OVERFLOW;
			// ...
		}

		IntegerDowngrade::~IntegerDowngrade() {
			if (pctx != NULL) {
				free(pctx);
			}
		}

		ERROR_T IntegerDowngrade::Execute(V_PARAS* args) {
			printf("integer downgrade execute...\n");

			uint32 size = 8;
			if (args->Flag == FLAG_INTEGER_OVERFLOW)
				VulnFunc(size - 9);
			if (args->Flag == FLAG_USHORT_OVERFLOW) {
				AppendUnicode(L"aaaaaaaaaaaaaaaa");
			}

			DPrint("normal over");
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
			char* buf = (char*)LocalAlloc(0x40, 8);
			__try
			{
				// stack overflow here
				memset(data, 0, size);
				dump_hex_top2("hex: ", data, ARRAYSIZE(data));
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

		void IntegerDowngrade::AppendUnicode(wchar_t* source) {

			long long len = 0xfff * lstrlenW(source) + 0x40;
			USHORT size = (USHORT)len;
			UNICODE_STRING unicodestr = { 0 };
			unicodestr.Buffer = (PWSTR)malloc(size);
			memset(unicodestr.Buffer, 0, size);
			unicodestr.Length = 0;
			unicodestr.MaximumLength = size;

			fnRtlAppendUnicodeToString fb = (fnRtlAppendUnicodeToString)GetProcAddress(GetModuleHandle(L"ntdll"), "RtlAppendUnicodeToString");
			NTSTATUS status = fb(&unicodestr, source);
			DPrint("RtlAppendUnicodeToString %d\n", status);
			hexdump2(unicodestr.Buffer, size);
			wprintf(L"%s\n", unicodestr.Buffer);
			free(unicodestr.Buffer);
		}
	}
}