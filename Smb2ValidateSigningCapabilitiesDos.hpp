/*
.reference
	https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43642


*/

#pragma once

#ifndef VULN_UAF_SMB2_DOS
#define VULN_UAF_SMB2_DOS
#endif

#include "log.hpp"
#include "common.hpp"


typedef struct _uaf_smb_dos_context {
	char Reverse[0xD8];
	char** address;
}uaf_smb_dos_context, * puaf_smb_dos_context;

namespace Vuln {
	namespace UseAfterFree {

		class Smb2Dos {
		public:
			Smb2Dos();

			int Execute(uaf_smb_dos_context* ctx, int stage);
		};

		Smb2Dos::Smb2Dos() {

		}

		int Smb2Dos::Execute(uaf_smb_dos_context* ctx, int stage) {
			if (stage == 0)
				*(char**)ctx->address = (char*)malloc(0x40);

			if (stage == 1) {
				free(*(char**)ctx->address);
				*(char**)ctx->address = NULL;
			}
		}
	}
}