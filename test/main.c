#include <Windows.h>
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

void _test3() {
	void* array[10];
	for (size_t i = 0; i < 10; i++)
	{
		array[i] = malloc(0x1000);
		printf("%p\n", array[i]);
	}

	for (size_t i = 0; i < 10; i++)
	{
		free(array[i]);
	}
}

void _rce() {
	HMODULE addr = LoadLibrary(L"\\\\BOPIN-PC\\smb\\CreatePowerShell64.dll");
	printf("%x\n", addr);
}

void* allocmem(int size) {
	void* buf = LocalAlloc(0x40, (unsigned int)(size + 16));
	if (!buf) { return 0x00; }
	return buf;
}

typedef UINT(*pWinExec)(LPCSTR lpCmdLine, UINT   uCmdShow);
typedef struct _vuln_context {
	void* rce_addr;
	int size;
}vuln_context, * pvuln_context;

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
	vuln_context* ctx = lpParameter;
	printf("thread => %p\n", ctx);
	ctx->size = 0xffffff;
	return 1;
}

void test5(const vuln_context* ctx) {
	int size = 0;

	void* buf = NULL;
	printf("test5 => %p\n", ctx);

	size = ctx->size;
	buf = allocmem(size);
	pWinExec pexec = ctx->rce_addr;
	if (ctx->size != 0x10)
		pexec("calc", 0);

	memcpy(buf, ctx, ctx->size);

	printf("%p %d\n", pexec, ctx->size);
}

void test6() {
	LARGE_INTEGER _s = { 0 };
	_s.HighPart = 0xffff;
	_s.LowPart = 0x1000;
	long long size = *(long long *) & _s;

	void* buf = HeapAlloc(GetProcessHeap(), 0x8, size);
}

LPVOID MemoryAlloc(size_t a1) {
	HANDLE ProcessHeap; // rax

	ProcessHeap = GetProcessHeap();
	return HeapAlloc(ProcessHeap, 0, a1);
}

void test7() {

}

int main() {

#ifdef DONT_EXECUTE
	_test1();
	_test2();
	_test3();
	_rce();

	char* tmp = "this is a test";
	printf("%s\n", tmp + -100);
#endif

#ifdef _TEST_ALLOC_MEMWRITE_DOUBLEFETCH
	vuln_context* vulnctx = allocmem(sizeof(vuln_context));
	vulnctx->rce_addr = WinExec;
	vulnctx->size = 16;

	printf("main => %p\n", vulnctx);

	HANDLE handle = CreateThread(0, 0, ThreadProc, vulnctx, 0, 0);
	SetThreadPriority(handle, THREAD_PRIORITY_TIME_CRITICAL);

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
	test5(vulnctx);
#endif


	LPVOID addr = MemoryAlloc(0x20);
	printf("%s\n", addr);

	HeapFree(GetProcessHeap(), 0, addr);
	return (0);
}