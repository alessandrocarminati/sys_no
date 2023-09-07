#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

#include "../include/uthash/src/utlist.h"
#include "../include/consts.h"
#include "../include/cfg.h"
#include "../include/global_defines.h"

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
		if ((curr==insn[i].address) && (i<instr_no-1)) return insn[i+1].address;
		}
	return 0;
}

struct Block *build_cfg(struct exec_item *f) {
	csh handle;
	cs_insn *insn;
	size_t count, jt_cnt=0;
	struct Block *first=NULL, *current, *app;
	int i;
	bool found, not_jmp_targets;
	uint64_t jump_targets[MAX_JT];

	DBG_PRINT("Initialize Capstone (%d,%d)\n", BT2CSARCH(f->bin_type), BT2CSMODE(f->bin_type));

	 if (cs_open(BT2CSARCH(f->bin_type), BT2CSMODE(f->bin_type), &handle) != CS_ERR_OK) {
		printf("Error initializing Capstone\n");
		return NULL;
		}

	// enable options
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)!=CS_ERR_OK) {
		printf("Error setting Capstone options\n");
		return NULL;
		}

	DBG_PRINT("Process text (%zu, %p, %d, %08lx, 0, %p)\n", handle, f->text, f->length, f->base_address, &insn);

	//get instructions
	count = cs_disasm(handle, f->text, f->length, f->base_address, 0, &insn);
	if (count <= 0) {
		printf("Error disassembling code -(%d)-\n", cs_errno(handle));
		cs_close(&handle);
		return NULL;
		}


	DBG_PRINT("Found %zu instructions\nCollect jump targets\n", count);

	// collect jump targets
	for (i = 0; i < count; i++) {
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) {
			update_jmp_targets(f, insn, i, count, jump_targets, &jt_cnt);
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
	current->instr_cnt=0;
	current->branch_addr=0;
	current->forward_addr=0;

	// iterate all instructions
	DBG_PRINT("Preliminary scan started\n");
	for (i = 0; i < count; i++) {
		current->instr_cnt++;
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) DBG_PRINT("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
		DBG_PRINT("Process instruction at 0x%08lx\n", insn[i].address);
		not_jmp_targets=not_in(insn[i].address, jump_targets, jt_cnt);
		if (cs_insn_group(handle, &insn[i], CS_GRP_INT)) {
			DBG_PRINT("Block starting at 0x%08x has syscall\n", current->start);
			current->syscall=1;
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) {
			DBG_PRINT("Block starting at 0x%08x has ret\n", current->start);
			current->ret=1;
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP) || !not_jmp_targets) {
			DBG_PRINT("Process instruction at 0x%08lx determine if forward or branch needs to be filled\n", insn[i].address);
			current->end=i<count-1?insn[i+1].address:f->base_address+f->length;
			if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) {
				update_blk_linkage(f, insn, i, current);
				}

			if (i+1 < count) {
				if (is_jmp(f,insn,i)) {
					DBG_PRINT("Hit Block termination @0x%08lx set forward_addr=0x%08lx\n", insn[i].address, insn[i+1].address);
					if (!current->ret) current->forward_addr=insn[i+1].address;
					}
				if ((app=(struct Block *) malloc(sizeof(struct Block)))==NULL){
					printf("Error Allocating memory\n");
					// TODO: check list and remove allocated stuff
					return NULL;
					};
				memset(app, 0, sizeof(struct Block));
				app->start=insn[i+1].address;
				app->syscall=false;
				app->branch_addr=0;
				app->forward_addr=0;
				app->instr_cnt=0;
				DL_APPEND(first, app);
				current=app;
				}
			}
		}
	cs_free(insn, count);
	cs_close(&handle);
	DBG_PRINT("Preliminar scan ended\n");

	DL_FOREACH(first,current) {
		found=false;
		DL_FOREACH(first,app){
			if ((current->branch_addr >= app->start) && (current->branch_addr < app->end)) {
				found=true;
				break;
				}
			}
		current->branch = found?app:NULL;

		if (app) DBG_PRINT("link 0x%08x and 0x%08x\n", current->start, app->start); else DBG_PRINT("branch 0x%08x not found\n", current->branch_addr);

		found=false;
		DL_FOREACH(first,app){
			if ((current->forward_addr >= app->start) && (current->forward_addr < app->end)) {
				found=true;
				break;
				}
			}
		current->forward=found?app:NULL;

		if (app) DBG_PRINT("link 0x%08x and 0x%08x\n", current->start, app->start); else DBG_PRINT("forward 0x%08x not found\n", current->forward_addr);

		}

	return first;
}


void print_plain_cfg(struct Block *root){
	struct Block *app;

	DL_FOREACH(root,app)  printf("Block: Start=0x%08x, End=0x%08x, instr_cnt=%d Syscall=%d, ret=%d, Next-Forward=0x%08x, Next-branch=0x%08x\n", app->start, app->end, app->instr_cnt, app->syscall, app->ret, app->forward_addr, app->branch_addr);
}

bool not_in(uint64_t c, uint64_t visited[], int visited_no){
	int i;

	for (i=0; i<visited_no; i++) {
		if (visited[i]== c) return false;
		}
	return true;
}

static int _print_dot(struct Block *current, char *dot, int *dot_len, uint64_t visited[], int *visited_no){
	char *color=NULL;

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

	visited.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
	dot= (char *) malloc(DOT_BUF_SIZE);
	dot_len += snprintf(dot+dot_len, DOT_BUF_SIZE-dot_len, "digraph G {\n");
	err=_print_dot(root, dot, &dot_len, visited.blocks, &(visited.blocks_no));
	dot_len += snprintf(dot+dot_len, DOT_BUF_SIZE-dot_len, "}\n");
	free(visited.blocks);
	return err==NO_ERROR?dot:ERR_BUFOVF_MSG;
}

bool is_call(struct exec_item *f, cs_insn *insn, int i){
	switch (f->bin_type){
	case BIN_X86_64: return insn[i].id != X86_INS_CALL;
	case BIN_ARM_64: {
		return insn[i].id != ARM64_INS_BL;
		}
	default: return false;
	}
}

bool is_jmp(struct exec_item *f, cs_insn *insn, int i){
	switch (f->bin_type){
	case BIN_X86_64: return insn[i].id != X86_INS_JMP;
	case BIN_ARM_64: {
//		return insn[i].id != ARM64_INS_B;
		return strncmp(insn[i].mnemonic,"b",5)!=0;
		}
	default: return false;
	}
}
void update_jmp_targets(struct exec_item *f, cs_insn *insn, int i, size_t count, uint64_t *jump_targets, size_t *jt_cnt){
	switch (f->bin_type){
	case BIN_X86_64: {
		cs_x86_op *op = &(insn[i].detail->x86.operands[0]);
		if (op->type == X86_OP_IMM) {
			DBG_PRINT("@%d instr adding jump_targets[%zu]=0x%08lx jmp dst\n", i, *jt_cnt, op->imm);
			if (prev_instr(op->imm, insn, count)>f->base_address) jump_targets[(*jt_cnt)++]=prev_instr(op->imm, insn, count);
			}
		}
	case BIN_ARM_64: {
		cs_arm64_op *op = &(insn[i].detail->arm64.operands[0]);
		if (op->type == ARM64_OP_IMM) {
			DBG_PRINT("Dump instruction @%08lx: mnemonic:'%s', operands:'%s' \n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
			DBG_PRINT("@%d instr adding jump_targets[%zu]=0x%08lx jmp dst\n", i, *jt_cnt, op->imm);
			if (prev_instr(op->imm, insn, count)>f->base_address) jump_targets[(*jt_cnt)++]=prev_instr(op->imm, insn, count);
			}
		}
	default: {}
	}
}
void update_blk_linkage(struct exec_item *f, cs_insn *insn, int i, struct Block *current){
	switch (f->bin_type){
	case BIN_X86_64: {
		cs_x86_op *op = &(insn[i].detail->x86.operands[0]);
		DBG_PRINT("Block ending at 0x%08lx is because a branch statement op->type=%d\n", insn[i].address, op->type);
			if (op->type == X86_OP_IMM) {
				// Direct jump or call
				DBG_PRINT("Hit Block termination @0x%08lx set branch_addr=0x%08lx\n", insn[i].address, op->imm);
				if (is_call(f,insn,i)) current->branch_addr=op->imm;
				}
			if (op->type == X86_OP_MEM) {
				// Indirect jump or call
				DBG_PRINT("Hit Block termination @0x%08lx set branch_addr=0x%08lx\n", insn[i].address, 1UL);
				if (is_call(f,insn,i)) current->branch_addr=1;
				}
		}
	case BIN_ARM_64: {
		cs_arm64_op *op = &(insn[i].detail->arm64.operands[0]);
		DBG_PRINT("Block ending at 0x%08lx is because a branch statement op->type=%d\n", insn[i].address, op->type);
			if (op->type == ARM64_OP_IMM) {
				// Direct jump or call
				DBG_PRINT("Hit Block termination @0x%08lx set branch_addr=0x%08lx\n", insn[i].address, op->imm);
				if (is_call(f,insn,i)) current->branch_addr=op->imm;
				}
			if (op->type == ARM64_OP_MEM) {
				// Indirect jump or call
				DBG_PRINT("Hit Block termination @0x%08lx set branch_addr=0x%08lx\n", insn[i].address, 1UL);
				if (is_call(f,insn,i)) current->branch_addr=1;
				}
		}
	default: {}
	}
}

