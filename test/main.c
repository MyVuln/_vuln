#include <stdio.h>
#include <string.h>

#pragma warning(disable : 4996);

void _test1() {
	char longString[] = "String signifying nothing";
	char shortString[16];
	memset(shortString, 0, 16);

	strncpy(shortString, longString, 16);
	printf("The last character in shortString is: %c (%1$x)\n", shortString[15]);
	printf("The last character in shortString is: %s\n", shortString);
}

void _test2() {
	char longString[] = "String signifying nothing";
	char shortString[160];

	strncpy(shortString, longString, strlen(longString) + 10);
	printf("The last character in shortString is: %c (%1$x)\n", shortString[15]);
	printf("The last character in shortString is: %s\n", shortString);

}

int main() {

	_test1();
	_test2();
	return (0);
}