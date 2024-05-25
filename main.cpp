#include "common.hpp"
#include "IntegerOverflow.hpp"

using namespace Vuln;

int main() {
	char* desc = "vuln exists\n";
	dump_hex_top(desc, strlen(desc));
	hexdump2(desc, strlen(desc));


	IntegerDowngrade* intd = new IntegerDowngrade();
	intd->Execute(NULL);

	delete intd;

}
