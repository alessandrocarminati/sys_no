#include <stdio.h>

int print_text_file(const char *fn) {
	FILE *fptr;
	char c;

	fptr = fopen(fn, "r");
	if (fptr == NULL) {
		printf("Cannot open file \n");
		return 1;
		}
	c = fgetc(fptr);
	while (c != EOF) {
		printf ("%c", c);
		c = fgetc(fptr);
		}
	fclose(fptr);
	return 0;
}
