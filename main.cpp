#include "common.hpp"
#include "IntegerOverflow.hpp"
#include "ArbitraryIncrement.hpp"
#include "DoubleFree.hpp"

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
};


int main(int argc, char* argv[]) {
	if (argc != 2) {
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
	else
	{

	}
}
