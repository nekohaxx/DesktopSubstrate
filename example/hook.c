#include <substrate.h>
int foo();

static int (*original_foo)();

int replacement_foo() {
	return original_foo() + 1;
}

static void __attribute__((constructor)) ctor() {
	DSHookFunction(foo, replacement_foo, &original_foo);
	DSUnhookFunction(foo);
}
