#pragma once

#ifndef CHEAPFACTORY
#define CHEAPFACTORY
#endif


namespace Vuln {
	class CHeapFactory
	{
	public:
		CHeapFactory();
		~CHeapFactory();

		void* Alloc(int flag, int size) {
			/*
				GetProcessHeap()
				HeapAlloc()

			*/
		}

		int Free(void* addr) {
			/*
			HeapFree
			*/
		}

		void Init() {
			/*
			HeapCreate
			*/
		}

		int Validate(void* addr) {
			/*
			RaiseException
			*/
		}

	private:

	};

	CHeapFactory::CHeapFactory()
	{
	}

	CHeapFactory::~CHeapFactory()
	{
	}
}