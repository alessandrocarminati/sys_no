#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

#include "uthash/src/utlist.h"
#include "sample_code.h"
#include "consts.h"

struct Block {
//	struct list_head node;
	int start;
	int end;
	bool syscall;
	struct Block *branch, *forward, *next, *prev;
	uint32_t branch_addr, forward_addr;
};

struct Block *list_blocks(unsigned char *code, size_t code_size, uint64_t start_address) {
	csh handle;
	cs_insn *insn;
	size_t count;
	struct Block *first=NULL, *current, *app;
	int i;


	 if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("Error initializing Capstone\n");
		return NULL;
		}

	// enable options
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	//get instructions
	count = cs_disasm(handle, code, code_size, start_address, 0, &insn);
	if (count <= 0) {
		printf("Error disassembling code\n");
		cs_close(&handle);
		return NULL;
		}

	current = (struct Block *) malloc(sizeof(struct Block));
	memset(current, 0, sizeof(struct Block));
	DL_APPEND(first, current);

	current->start=insn[0].address;
	current->syscall=false;
	current->branch_addr=0;
	current->forward_addr=0;

	// iterate all instructions
	for (i = 0; i < count; i++) {
		if (cs_insn_group(handle, &insn[i], CS_GRP_INT)) current->syscall=true;
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP) || cs_insn_group(handle, &insn[i], CS_GRP_CALL)) {
			current->end=insn[i].address;
			cs_x86_op *op = &(insn[i].detail->x86.operands[0]);

			if (op->type == X86_OP_IMM) {
				// Direct jump or call
				if (insn[i].id != X86_INS_CALL) current->branch_addr=op->imm;
				}
			if (op->type == X86_OP_MEM) {
				// Indirect jump or call
				if (insn[i].id != X86_INS_CALL) current->branch_addr=1;
				}
			if (i+1 < count) {
				if (insn[i].id != X86_INS_JMP) current->forward_addr=insn[i+1].address;
				if ((app=(struct Block *) malloc(sizeof(struct Block)))==NULL){
					printf("malloc error\n");
					return NULL;
					};
				memset(app, 0, sizeof(struct Block));
				app->start=insn[i+1].address;
				app->syscall=false;
				app->branch_addr=0;
				app->forward_addr=0;
				DL_APPEND(first, app);
				current=app;
				}
			}
		}
	cs_free(insn, count);
	cs_close(&handle);


	DL_FOREACH(first,current) {
		DL_SEARCH_SCALAR(first,app,start,current->branch_addr);
		current->branch=app;
		DL_SEARCH_SCALAR(first,app,start,current->forward_addr);
		current->forward=app;
		}

	return first;
}



int main(){
	struct Block *root, *app;

	root=list_blocks(function, sizeof(function), BASE_ADDRESS);
	DL_FOREACH(root,app)  printf("Block: Start=0x%08x, End=0x%08x, Syscall=%d, Next-Forward=0x%08x, Next-branch=0x%08x\n", app->start, app->end, app->syscall, app->forward_addr, app->branch_addr);
}
