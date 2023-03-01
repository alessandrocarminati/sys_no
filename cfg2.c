#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

#include "uthash/src/utlist.h"
#include "sample_code.h"
#include "consts.h"

struct Block {
	int start;
	int end;
	unsigned int syscall : 1;
	unsigned int ret : 1;
	struct Block *branch, *forward, *next, *prev;
	uint32_t branch_addr, forward_addr;
};

struct block_list {
	uint64_t blocks[MAX_BLOCS];
	int	blocks_no;
};

struct Block *build_cfg(unsigned char *code, size_t code_size, uint64_t start_address) {
	csh handle;
	cs_insn *insn;
	size_t count;
	struct Block *first=NULL, *current, *app;
	int i;
	bool found;


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
	current->syscall=0;
	current->ret=0;
	current->branch_addr=0;
	current->forward_addr=0;

	// iterate all instructions
	for (i = 0; i < count; i++) {
		if (cs_insn_group(handle, &insn[i], CS_GRP_INT)) current->syscall=1;
		if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) current->ret=1;
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
					printf("Error Allocating memory\n");
					// TODO: check list and remove allocated stuff
					return 0;
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
		found=false;
		DL_FOREACH(first,app){
			if ((current->branch_addr >= app->start) && (current->branch_addr <= app->end)) {
				found=true;
				break;
				}
			}
		current->branch = found?app:NULL;
#ifdef DEBUG
if (app) printf("link 0x%08x and 0x%08x\n", current->start, app->start); else printf("branch 0x%08x not found\n", current->branch_addr);
#endif
		found=false;
		DL_FOREACH(first,app){
			if ((current->forward_addr >= app->start) && (current->forward_addr <= app->end)) {
				found=true;
				break;
				}
			}
		current->forward=found?app:NULL;
#ifdef DEBUG
if (app) printf("link 0x%08x and 0x%08x\n", current->start, app->start); else printf("forward 0x%08x not found\n", current->forward_addr);
#endif
		}

	return first;
}


void print_plain_cfg(struct Block *root){
	struct Block *app;

	DL_FOREACH(root,app)  printf("Block: Start=0x%08x, End=0x%08x, Syscall=%d, Next-Forward=0x%08x, Next-branch=0x%08x\n", app->start, app->end, app->syscall, app->forward_addr, app->branch_addr);
}

static bool not_visited(uint64_t c, uint64_t visited[], int visited_no){
	int i;

	for (i=0; i<visited_no; i++) {
		if (visited[i]== c) return false;
		}
	return true;
}

static void _print_dot(struct Block *current, char *dot, int *dot_len, uint64_t visited[], int *visited_no){

	visited[(*visited_no)++]=current->start;

	if (current->syscall) (*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE, " \"0x%08x\" [shape=box style=filled fillcolor=green]\n", current->start);
	if (current->ret) (*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE, " \"0x%08x\" [shape=box style=filled fillcolor=red]\n", current->start);

	if (current->forward) {
		if (!current->ret) (*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE, " \"0x%08x\" -> \"0x%08x\"\n", current->start, current->forward->start);
		if (not_visited(current->forward->start, visited, (*visited_no))) {
			_print_dot(current->forward, dot, dot_len, visited, visited_no);
			}
		}
	if (current->branch) {
		(*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE, " \"0x%08x\" -> \"0x%08x\"[color=red]\n", current->start, current->branch->start);
		if (not_visited(current->branch->start, visited, (*visited_no))) {
			_print_dot(current->branch, dot, dot_len, visited, visited_no);
			}
		}

}

char *cfg2dot(struct Block *root){
	char *dot;
	struct block_list visited = {.blocks_no=0};
	int dot_len=0;

	dot= (char *) malloc(DOT_BUF_SIZE);
	dot_len += snprintf(dot+dot_len, DOT_BUF_SIZE, "digraph G {\n");
	_print_dot(root, dot, &dot_len, visited.blocks, &(visited.blocks_no));
	dot_len += snprintf(dot+dot_len, DOT_BUF_SIZE, "}\n");
	return dot;
}


int main(){
	struct Block *root;
	root=build_cfg(function, sizeof(function), BASE_ADDRESS);
	print_plain_cfg(root);
	printf("%s", cfg2dot(root));
}
