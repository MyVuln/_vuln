#include "common.hpp"
#include "IntegerOverflow.hpp"
#include "ArbitraryIncrement.hpp"
#include "DoubleFree.hpp"
#include "UAF.hpp"
#include "NullPointerDereference.hpp"
#include "IMemoryLeak.hpp"
#include "InfoDisclosure.hpp"
#include "ArbitraryRead.hpp"
#include "UninitializeMemory.hpp"
#include "DoubleFetch.hpp"
#include "NonZeroEnd.hpp"
#include "TypeConfustionExample.hpp"
#include "COMFusion.hpp"
#include "UseVictim.hpp"
#include "NumbericTrancation.hpp"
#include "HeapOverflowExploitation.hpp"

using namespace Vuln;
using namespace Vuln::OutofBoundRead;
using namespace Vuln::OutofBoundWrite;
using namespace Vuln::RaceCondition;
using namespace Vuln::TypeConfusion;
using namespace Vuln::UseAfterFree;
using namespace Vuln::IntegerOverflow;

template <typename T>
struct InputModel {
	USHORT Index;
	char* Name;
	const char* Description;
};

const InputModel<VulnBase> Models[] = {
	{0,"IntegerDowngrade",""},
	{1,"ArbitraryIncrement",""},
	{2,"DoubleFree",""},
	{3,"UAF",""},
	{31,"MS_T120_UAF",""},
	{4,"NullPointerDereference",""},
	{5,"InfoDisclosure","xx 5 [len]"},
	{6,"ArbitraryRead","xx 6 [address] [len]"},
	{7,"UninitializeMemory",""},
	{8,"DoubleFetch",""},
	{9,"NonZeroEnd",""},
	{10,"TypeConfustionExample",""},
	{11,"COMFusion","xx 11 [address]"},
	{12,"NumbericTrancation","size"},
	{13,"HeapOverflowExploitation",""},
};

LONG WINAPI
VectoredHandler_FormatStackFrames(
	struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
	UNREFERENCED_PARAMETER(ExceptionInfo);
	PCONTEXT Context = ExceptionInfo->ContextRecord;
	EPrint("exception occurred!")
	printf("rax: %p\trbx: %p\nrcx: %p\trdx: %p\t\nr8: %p\tr9: %p\nrsp: %p\trbp: %p\n", Context->Rax, Context->Rbx, Context->Rcx, Context->Rdx, Context->R8, Context->R9, Context->Rsp, Context->Rbp);
	printf("rip: %p\n", Context->Rip);
	Utility::PrintStackTrace();
	return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		for (size_t i = 0; i < ARRAYSIZE(Models); i++)
		{
			auto v = Models[i];
			printf("%d  %s  %s\n",v.Index,v.Name,v.Description);
		}
		return -1;
	}
	PVOID h = AddVectoredExceptionHandler(0, VectoredHandler_FormatStackFrames);

	char* desc = "vuln exists\n";
	dump_hex_top(desc, strlen(desc));
	hexdump2(desc, strlen(desc));
	USHORT input = atoi(argv[1]);
	int last = argc - 1;
	USHORT flag = atoi(argv[last]);
	V_PARAS* args = (V_PARAS*)malloc(sizeof(V_PARAS));
	args->Address = NULL;
	args->Count = NULL;
	args->Flag = flag;

	if (input == 0) {
		SendVuln(IntegerDowngrade, args)
	}
	else if (input == 1) {
		SendVuln(ArbitraryIncrement, args)
	}
	else if (input == 2) {
		SendVuln(DoubleFree, args)
	}
	else if (input == 3) {
		SendVuln(UAF, args)
	}
	else if (input == 31) {
		SendVuln(MS_T120_UAF, args)
	}
	else if (input == 4) {
		SendVuln(NullPointerDereference, args)
	}
	else if (input == 5) {
		USHORT number = atoi(argv[2]);

		IMemoryLeak* leak = new InfoDisclosure();
		DWORD size = 64;
		LPVOID addr = leak->Alloc(size);	
		memset(addr, 0x41, size);
		leak->SetType(_InfoDisclosure);
		V_PARAS* paras = (V_PARAS*)malloc(sizeof(paras));
		paras->Address = addr;
		paras->Count = number;
		leak->Execute(paras);
		leak->Dispose(paras);
	}
	else if (input == 6) {
		USHORT number = atoi(argv[2]);
		USHORT type = atoi(argv[3]);
		IMemoryLeak* leak = new ArbitraryRead();
		DWORD size = 64;
		LPVOID addr = leak->Alloc(size);
		memset(addr, 0x41, size);
		leak->SetType(_ArbitraryRead);
		V_PARAS* paras = (V_PARAS*)malloc(sizeof(paras));
		paras->Address = ((ArbitraryRead*)leak)->GetMemAddress(type, addr);
		paras->Count = number;
		leak->Execute(paras);
		leak->Dispose(paras);
	}
	else if (input == 7) {
		SendVuln(UninitializeMemory, args);
	}
	else if (input == 8) {
		args->Count = 0x10;
		args->Address = (PVOID)0x4141414141414141;
		args->FlagFeatures.CompilerOptimise = 1;
		args->FlagFeatures.Reserved = 0;
		SendVuln(DoubleFetch, args);
	}
	else if (input == 9) {
		SendVuln(NonZeroEnd,args);
	}
	else if (input == 10)
	{
		SendVuln(TypeConfustionExample, args);
	}
	else if (input == 11)
	{
		args->Count = 0x7ffe0000;
		SendVuln(COMFusion, args);
	}
	else if (input == 12)
	{
		args->Count = atoi(argv[2]);
		args->Address = malloc(args->Count);
		printf("count: 0x%x\naddr: %p\n", args->Count,args->Address);
		memset(args->Address, 0x41, args->Count);
		SendVuln(NumbericTrancation, args);
		if (args->Address) {
			// memory corruption
			SIZE_T count = args->Count;
			PVOID addr = args->Address;
			printf("[free] count: 0x%x\naddr: %p\n", count,addr);
			free(args->Address);
			args->Address = NULL;
		}
	}
	else if (input == 13) {
		SendVuln(HeapOverflowExploitation, args)
	}
	else
	{
		for (size_t i = 0; i < ARRAYSIZE(Models); i++)
		{
			printf("%d %s %s\n", Models[i].Index, Models[i].Name, Models[i].Description);
		}
	}
	RemoveVectoredExceptionHandler(h);
	DPrint("normal over")
}