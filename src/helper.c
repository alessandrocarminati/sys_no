#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/global_defines.h"

#define BACKTRACE_DEPTH 50

void print_trace (void) {
#ifdef DEBUG
	void *array[BACKTRACE_DEPTH];
	char **strings;
	int size, i;

	size = backtrace (array, BACKTRACE_DEPTH);
	strings = backtrace_symbols (array, size);
	if (strings != NULL) {
		printf ("Obtained %d stack frames.\n", size);
		for (i = 0; i < size; i++) printf ("%s\n", strings[i]);
		}
	free (strings);
#endif
	return;
}
