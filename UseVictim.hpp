#pragma once

#ifndef VULN_OOBW_USEVICTIM
#define VULN_OOBW_USEVICTIM
#endif


#include "log.hpp"
#include "common.hpp"

#define BUF_SIZE 0x10

namespace Vuln {
	namespace OutofBoundWrite {

		/**
		*
		* https://i.blackhat.com/BH-US-24/Presentations/US24-Qian-PageJack-A-Powerful-Exploit-Technique-With-Page-Level-UAF-Thursday.pdf
		*
		*/

		// out-of-bound write  struct object
		typedef struct _oobw_obj {
			unsigned int id;
			void* addr;
		}oobw_obj, * poobw_obj;

		// fake object for attacking
		// 1. trigger the vuln  out-of-write  oobw_obj memory boundary to arrive  oobw_victim
		typedef struct _oobw_victim_obj {
			void* callback;
		}oobw_victim_obj, * poobw_victim_obj;




		class UseVictim
		{
		public:
			UseVictim();
			~UseVictim();
		public:
			ERROR_T Execute(V_PARAS* args);
		private:
			ERROR_T SetData(void* data, int size);
			oobw_obj* _obj;
		private:
		};

		UseVictim::UseVictim()
		{
		}


		UseVictim::~UseVictim()
		{
			if (_obj) {
				free(_obj);
				_obj = NULL;
			}
		}

		ERROR_T UseVictim::Execute(V_PARAS* args) {
#ifdef SECURE

#else
			wchar_t* buf = 0;
			int outsize = 0;
			DPrint("information disclosure size: 0x%x %d", outsize, outsize);
			hexdump2(buf, outsize);
#endif
			return 0x40000001;
		}

		ERROR_T UseVictim::SetData(void* data, int size) {
			_obj = (oobw_obj*)malloc(sizeof(oobw_obj));
			hexdump2(_obj, sizeof(oobw_obj));
			if (*(int*)data != 0x43434242) {
				DPrint("magic is valid");
				return 0x01;
			}

			// heap fengshui to set  victim object memory location

			// write data to trigger oob-write vuln

			// broken  victim  data


			return 0x00;
		}
	}
}