#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

#include "uthash/src/utlist.h"
#include "consts.h"
#include "cfg.h"

static uint64_t prev_instr(uint64_t curr, cs_insn *insn, int instr_no){
	int i;

	for (i = 0; i < instr_no; i++) {
		if ((curr==insn[i].address) && (i>0)) return insn[i-1].address;
		}
	return 0;
}

static uint64_t next_instr(uint64_t curr, cs_insn *insn, int instr_no){
	int i;

	for (i = 0; i < instr_no; i++) {
		if ((curr==insn[i].address) && (i<instr_no)) return insn[i+1].address;
		}
	return 0;
}

struct Block *build_cfg(struct exec_item *f) {
	csh handle;
	cs_insn *insn;
	size_t count, jt_cnt=0;
	struct Block *first=NULL, *current, *app;
	int i;
	bool found, is_jmp_targets;
	uint64_t jump_targets[MAX_JT];

	DBG_PRINT("Initialize Capstone\n");

	 if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("Error initializing Capstone\n");
		return NULL;
		}

	// enable options
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	DBG_PRINT("Process text\n");

	//get instructions
	count = cs_disasm(handle, f->text, f->length, f->base_address, 0, &insn);
	if (count <= 0) {
		printf("Error disassembling code\n");
		cs_close(&handle);
		return NULL;
		}


	DBG_PRINT("Found %zu instructions\nCollect jump targets\n", count);

	// collect jump targets
	for (i = 0; i < count; i++) {
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP) || cs_insn_group(handle, &insn[i], CS_GRP_CALL)) {
			cs_x86_op *op = &(insn[i].detail->x86.operands[0]);
			if (op->type == X86_OP_IMM) {
				DBG_PRINT("@%d instr adding jump_targets[%zu]=0x%08lx jmp dst\n", i, jt_cnt, op->imm);
				if (prev_instr(op->imm, insn, count)>f->base_address) jump_targets[jt_cnt++]=prev_instr(op->imm, insn, count);
				}
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) {
			DBG_PRINT("@%d instr adding jump_targets[%zu]=0x%08lx ret\n", i, jt_cnt, next_instr(insn[i].address, insn, count));
			jump_targets[jt_cnt++]=insn[i].address;
			}
		}


	DBG_PRINT("found %zu jup targets\n", jt_cnt);

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
		DBG_PRINT("Process instruction at 0x%08lx\n", insn[i].address);
		is_jmp_targets=not_in(insn[i].address, jump_targets, jt_cnt);
		if (cs_insn_group(handle, &insn[i], CS_GRP_INT)) {
			DBG_PRINT("Block starting at 0x%08lx has syscall\n", current->start);
			current->syscall=1;
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) {
			DBG_PRINT("Block starting at 0x%08lx has ret\n", current->start);
			current->ret=1;
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP) || cs_insn_group(handle, &insn[i], CS_GRP_CALL) || !is_jmp_targets) {
			current->end=insn[i].address;
			cs_x86_op *op = &(insn[i].detail->x86.operands[0]);

			if (is_jmp_targets) {
				if (op->type == X86_OP_IMM) {
					// Direct jump or call
					DBG_PRINT("Hit Block termination set branch_addr=0x%08lx\n", op->imm);
					if (insn[i].id != X86_INS_CALL) current->branch_addr=op->imm;
					}
				if (op->type == X86_OP_MEM) {
					// Indirect jump or call
					DBG_PRINT("Hit Block termination set branch_addr=0x%08lx\n", 1);
					if (insn[i].id != X86_INS_CALL) current->branch_addr=1;
					}
				}
			if (i+1 < count) {
				if (insn[i].id != X86_INS_JMP) {
					DBG_PRINT("Hit Block termination set forward_addr=0x%08lx\n", insn[i+1].address);
					current->forward_addr=insn[i+1].address;
					}
				if ((app=(struct Block *) malloc(sizeof(struct Block)))==NULL){
					printf("Error Allocating memory\n");
					// TODO: check list and remove allocated stuff
					return 0;
					};
				memset(app, 0, sizeof(struct Block));
//				app->start=insn[i].address;
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

		if (app) DBG_PRINT("link 0x%08x and 0x%08x\n", current->start, app->start); else printf("branch 0x%08x not found\n", current->branch_addr);

		found=false;
		DL_FOREACH(first,app){
			if ((current->forward_addr >= app->start) && (current->forward_addr <= app->end)) {
				found=true;
				break;
				}
			}
		current->forward=found?app:NULL;

		if (app) DBG_PRINT("link 0x%08x and 0x%08x\n", current->start, app->start); else printf("forward 0x%08x not found\n", current->forward_addr);

		}

	return first;
}


void print_plain_cfg(struct Block *root){
	struct Block *app;

	DL_FOREACH(root,app)  printf("Block: Start=0x%08x, End=0x%08x, Syscall=%d, ret=%d, Next-Forward=0x%08x, Next-branch=0x%08x\n", app->start, app->end, app->syscall, app->ret, app->forward_addr, app->branch_addr);
}

static bool not_in(uint64_t c, uint64_t visited[], int visited_no){
	int i;

	for (i=0; i<visited_no; i++) {
		if (visited[i]== c) return false;
		}
	return true;
}

static int _print_dot(struct Block *current, char *dot, int *dot_len, uint64_t visited[], int *visited_no){
	unsigned char *color=NULL;

	visited[(*visited_no)++]=current->start;

	if ((current->syscall) && (current->ret) ) color="yellow";
		else {
			if (current->syscall) color="green";
			if (current->ret)  color="red";
			}

	if (color && (DOT_BUF_SIZE-*dot_len>0)) (*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE-*dot_len, " \"0x%08x\" [shape=box style=filled fillcolor=%s]\n", current->start, color);

	if (current->forward) {
		if (DOT_BUF_SIZE-*dot_len>0) (*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE-*dot_len, " \"0x%08x\" -> \"0x%08x\"\n", current->start, current->forward->start);
		if (not_in(current->forward->start, visited, (*visited_no))) {
			_print_dot(current->forward, dot, dot_len, visited, visited_no);
			}
		}
	if (current->branch) {
		 if (DOT_BUF_SIZE-*dot_len>0) (*dot_len) += snprintf(dot+(*dot_len), DOT_BUF_SIZE-*dot_len, " \"0x%08x\" -> \"0x%08x\"[color=red]\n", current->start, current->branch->start);
		if (not_in(current->branch->start, visited, (*visited_no))) {
			_print_dot(current->branch, dot, dot_len, visited, visited_no);
			}
		}
	return DOT_BUF_SIZE-*dot_len>0?NO_ERROR:ERR_BUFOVF;
}


//dot output is provided in an allocated memory. User is required to free it up as needed.
char *cfg2dot(struct Block *root){
	char *dot;
	struct block_list visited = {.blocks_no=0};
	int err, dot_len=0;

	visited.blocks=(uint64_t *) malloc(MAX_BLOCS*sizeof(uint64_t));
	dot= (char *) malloc(DOT_BUF_SIZE);
	dot_len += snprintf(dot+dot_len, DOT_BUF_SIZE-dot_len, "digraph G {\n");
	err=_print_dot(root, dot, &dot_len, visited.blocks, &(visited.blocks_no));
	dot_len += snprintf(dot+dot_len, DOT_BUF_SIZE-dot_len, "}\n");
	free(visited.blocks);
	return err==NO_ERROR?dot:ERR_BUFOVF_MSG;
}
