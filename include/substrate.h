#ifndef _DESKTOP_SUBSTRATE
#define _DESKTOP_SUBSTRATE
void DSHookFunction(void *func, void *replace, void *orig);
void DSUnhookFunction(void *func);
#endif
