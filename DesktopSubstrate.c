//
// DesktopSubstrate.c
//
// Copyright © 2025 nekohaxx. All rights reserved.
// You may not redistribute the software in any form, whether modified or unmodified, or use it in your projects without prior approval.
//


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <capstone/capstone.h>

#define ENDBR64 0xfa1e0ff3U

struct DSHook {
	void *func;
	size_t patchsize;
	void *newfunc;
	size_t newfuncsize;
	struct DSHook *next;
};

struct DSHook *DSHooks = NULL;

int DSGetPatchSize(void *address) {
	csh handle;
	cs_insn *insn;
	size_t total_size = 0;
	size_t byte_count = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("Failed to initialize Capstone.\n");
		return -1;
	}

	int count = 0;
	while (byte_count < 5) {
		count = cs_disasm(handle, (const uint8_t *)address + total_size, 15, (uint64_t)address + total_size, 1, &insn);
		if (count <= 0) {
			break;
		}

		total_size += insn[0].size;

		if (insn[0].id == X86_INS_ENDBR64) {
			continue;
		}

		byte_count += insn[0].size;
	}

	cs_free(insn, count);
	cs_close(&handle);

	return total_size;
}

int DSGetMemoryRegion(void *addr, void **region_start, size_t *region_size) {
	FILE *maps_file = fopen("/proc/self/maps", "r");
	if (maps_file == NULL) {
		perror("fopen");
		return -1;
	}

	char line[256];
	unsigned long start, end;
	int found = 0;

	while (fgets(line, sizeof(line), maps_file)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if ((unsigned long)addr >= start && (unsigned long)addr < end) {
				*region_start = (void *)start;
				*region_size = end - start;
				found = 1;
				break;
			}
		}
	}

	fclose(maps_file);

	if (!found) {
		return -1;
	}

	return 0;
}

void DSHookFunction(void *func, void *replace, void **orig) {
	void *region_start;
	size_t region_size;

	struct DSHook *hook = DSHooks;
	while (hook != NULL) {
		if (hook->func == func) return;
		hook = hook->next;
	}

	if (DSGetMemoryRegion(func, &region_start, &region_size) == -1) {
		if (orig != NULL) {
			*orig = NULL;
		}
		return;
	}

	int patchSize = DSGetPatchSize(func);
	bool endbr64 = *((uint32_t*)func) == ENDBR64;

	void *newfunc = NULL;
	size_t size;

	if (orig != NULL) {
		size = patchSize + 5;
		newfunc = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		memcpy(newfunc, func, patchSize);
		void *jmpAddr = newfunc + patchSize;
		*((uint8_t*)jmpAddr) = 0xE9;
		*((int32_t*)(jmpAddr + 1)) = func + patchSize - jmpAddr - 5; // TODO: ???
		mprotect(newfunc, size, PROT_READ | PROT_EXEC);
		*orig = newfunc;
	} else {
		newfunc = malloc(patchSize);
		memcpy(newfunc, func, patchSize);
	}

	mprotect(region_start, region_size, PROT_READ | PROT_WRITE);

	void *patchAddr = endbr64 ? (func + 4) : func;
	*((uint8_t*)patchAddr) = 0xE9;
	*((int32_t*)(patchAddr + 1)) = replace - patchAddr - 5; // TODO: ???

	mprotect(region_start, region_size, PROT_READ | PROT_EXEC);

	struct DSHook *newhook = malloc(sizeof(struct DSHook));
	newhook->func = func;
	newhook->patchsize = patchSize;
	newhook->newfunc = newfunc;
	newhook->newfuncsize = size;
	newhook->next = DSHooks;
	DSHooks = newhook;
}

void DSUnhookFunction(void *func) {
	void *region_start;
	size_t region_size;

	struct DSHook *hook = DSHooks;
	struct DSHook **previousHook = &DSHooks;
	while (hook != NULL) {
		if (hook->func == func) {
			if (DSGetMemoryRegion(func, &region_start, &region_size) == -1) {
				return;
			}
			mprotect(region_start, region_size, PROT_READ | PROT_WRITE);
			memcpy(func, hook->newfunc, hook->patchsize);
			mprotect(region_start, region_size, PROT_READ | PROT_EXEC);
			if (hook->patchsize == 0) {
				free(hook->newfunc);
			} else {
				munmap(hook->newfunc, hook->newfuncsize);
			}
			*previousHook = hook->next;
			free(hook);
			return;
		}
		hook = hook->next;
		previousHook = &hook->next;
	}
}
