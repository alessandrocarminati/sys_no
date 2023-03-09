#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

char test1[] = {0x0f, 0x8f, 0x92, 0x25, 0x0a, 0x00};
char test2[] = {0x0f, 0x8e, 0x8c, 0x25, 0x0a, 0x00};


uint16_t x86_j_near[]=
	{0x800F, 0x810F, 0x880F, 0x890F, 0x840F, 0x850F, 0x820F, 0x830F, 0x860F, 0x870F, 0x8C0F, 0x8D0F, 0x8E0F, 0x8F0F, 0x8A0F, 0x8B0F};
uint8_t x86_j_short[]=
	{0x70, 0x71, 0x78, 0x79, 0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0x7A, 0x7B};

bool x86_invert_jump(uint8_t *insn){
	int i;

	for (i=0; i<sizeof(x86_j_near); i++) {
		if (*((uint16_t *)insn)==x86_j_near[i]) {
			*((uint16_t *)insn)=x86_j_near[i^1];
			return true;
			}
		}
	for (i=0; i<sizeof(x86_j_short); i++) {
		if (*((uint8_t *)insn)==x86_j_short[i]) {
			*((uint8_t *)insn)=x86_j_short[i^1];
			return true;
			}
		}
	return false;
}

void printinstr(uint8_t *c){
	int i;

	for (i=0; i<sizeof(c); i++) printf("0x%02x, ", c[i]);
	printf("\n");
}

int main(){

	printinstr(test1);
	x86_invert_jump(test1);
	printinstr(test1);
	x86_invert_jump(test1);
	printinstr(test1);
	printf("--------------------------\n");
	printinstr(test2);
	x86_invert_jump(test2);
	printinstr(test2);
	x86_invert_jump(test2);
	printinstr(test2);
}
