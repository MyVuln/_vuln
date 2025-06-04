#pragma once

#ifndef VULN_TYPECONFUSION
#define VULN_TYPECONFUSION
#endif


#include "log.hpp"
#include "common.hpp"

namespace Vuln {

	// parent class
	class Base {
	public:
		virtual void childdo() = 0;
	};

	class Execute : public Base {
	public:
		virtual void exec(const char* program) {
			system(program);
		}
		virtual void talk(const char* str) {
			printf("%s\n", str);
		}
		virtual void childdo() override{
			printf("i'm child\n");
		}
	};
	class Greeter : public Base {
	public:
		virtual void sayHi(const char* str) {
			printf("%s\n",str);
		}
		virtual void cmd(const char* program) {
			system(program);
		}
		virtual void childdo() override {
			printf("i'm child\n");
		}
	};

	class TypeConfustionExample {
	public:
		TypeConfustionExample();
		~TypeConfustionExample();
	public:
		ERROR_T Execute(V_PARAS* args);
	};
	
	TypeConfustionExample::TypeConfustionExample() {

	}

	TypeConfustionExample::~TypeConfustionExample() {

	}

	ERROR_T TypeConfustionExample::Execute(V_PARAS* args) {
		Base* b1 = new Greeter();
		Base* b2 = new Vuln::Execute();
		//DebugBreak();
#ifdef DEBUGLOG
		printf("greeter obj: 0x%x\n", b1);
		printf("execute obj: 0x%x\n", b2);
#endif

		Greeter* g = nullptr;
		g = static_cast<Greeter*>(b1);
		void (**vt)() = *(void (***)())g;
		void (**vt1)() = *(void (***)())b1;
		void (**vt2)() = *(void (***)())b2;
		g->sayHi("normal test");

#ifdef DEBUGLOG
		printf("exp obj: 0x%p\n", g);
		printf("exp obj: 0x%p\n", g + 8);
		printf("exp obj: 0x%p\n", g + 0x10);
#endif

		g = static_cast<Greeter*>(b2);
		g->sayHi("calc");

#ifdef DEBUGLOG
		printf("exp obj: 0x%p\n", g);
#endif

		delete b1;
		delete b2;
		return 0;
	}
}