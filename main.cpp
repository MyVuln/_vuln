#include "common.hpp"
#include "IntegerOverflow.hpp"
#include "ArbitraryIncrement.hpp"
#include "DoubleFree.hpp"
#include "UAF.hpp"
#include "NullPointerDereference.hpp"
#include "IMemoryLeak.hpp"
#include "InfoDisclosure.hpp"

using namespace Vuln;

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
	{4,"NullPointerDereference",""},
	{5,"InfoDisclosure","xx 5 [len]"},
};


int main(int argc, char* argv[]) {
	if (argc < 2) {
		for (size_t i = 0; i < ARRAYSIZE(Models); i++)
		{
			auto v = Models[i];
			printf("%d  %s  %s\n",v.Index,v.Name,v.Description);
		}
		return -1;
	}

	char* desc = "vuln exists\n";
	dump_hex_top(desc, strlen(desc));
	hexdump2(desc, strlen(desc));
	USHORT input = atoi(argv[1]);
	if (input == 0) {
		SendVuln(IntegerDowngrade)
	}
	else if (input == 1) {
		SendVuln(ArbitraryIncrement)
	}
	else if (input == 2) {
		SendVuln(DoubleFree)
	}
	else if (input == 3) {
		SendVuln(UAF)
	}
	else if (input == 4) {
		SendVuln(NullPointerDereference)
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
	else
	{
		for (size_t i = 0; i < ARRAYSIZE(Models); i++)
		{
			printf("%d %s %s\n", Models[i].Index, Models[i].Name, Models[i].Description);
		}
	}
}
