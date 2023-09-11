#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

#include "../include/uthash/src/utlist.h"
#include "../include/consts.h"
#include "../include/cfg.h"
#include "../include/global_defines.h"

const char multibyte_nop_x86[]=
		"\x90"
		"\x66\x90"
		"\x0f\x1f\x00"
		"\x0f\x1f\x40\x00"
		"\x66\x66\x66\x66\x90"
		"\x66\x0f\x1f\x44\x00\x00"
		"\x0f\x1f\x80\x00\x00\x00\x00"
		"\x0f\x1f\x84\x00\x00\x00\x00\x00"
		"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00";

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


void patch_syscall_at(struct exec_item *f, uint64_t addr)
{
	DBG_PRINT("syscall patching, write 2 bytes nop at 0x%lx\n", addr);
	*(f->text + addr) = *(MBNOP(2));
	*(f->text + addr + 1) = *(MBNOP(2) + 1);
}

void patch_instr(cs_insn *insn, struct exec_item *f)
{
	unsigned int i;

	DBG_PRINT("patching instr at 0x%lx, (%s). multibyte_nop_x86=%p, MBNOP(%d)=%p\n", insn->address, insn->mnemonic, multibyte_nop_x86, insn->size, MBNOP(insn->size));
	for (i=0; i<insn->size; i++)
		*(f->text + insn->address - f->base_address + i) = *(MBNOP(insn->size) + i);
}

void print_hex_text(struct exec_item *f)
{
	unsigned int i;

	for (i=0; i< f->length; i++)
		printf( (i & 0xf) == 0xf ? " %02x\n":" %02x", *(f->text+i));
	printf("\n");
}

void patch_calls(struct exec_item *f)
{
	size_t count, i;
	cs_insn *insn;
	csh handle;


	DBG_PRINT("Initialize Capstone\n");

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("Error initializing Capstone\n");
		return;
	}

	// enable options
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	DBG_PRINT("Patching calls\n");

	//get instructions
	count = cs_disasm(handle, f->text, f->length, f->base_address, 0, &insn);
	if (count <= 0) {
		DBG_PRINT("Error disassembling code\n");
		cs_close(&handle);
		return;
	}


	DBG_PRINT("Found %zu instructions\nProcessing the text\n", count);
	for (i = 0; i < count; i++) {
		if (cs_insn_group(handle, &insn[i], CS_GRP_CALL)) {
			DBG_PRINT("call 0x%lx, size %d detected\n", insn[i].address, insn[i].size);
			patch_instr(&insn[i], f);
		}
	}

	cs_free(insn, count);
	cs_close(&handle);
	return;
}

struct Block *build_cfg(struct exec_item *f) {
	csh handle;
	cs_insn *insn;
	size_t count, i, jt_cnt=0;
	struct Block *first=NULL, *current, *app;
	int blk_cnt=0;
	bool found, not_jmp_targets;
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
		DBG_PRINT("Error disassembling code\n");
		cs_close(&handle);
		return NULL;
		}


	DBG_PRINT("Found %zu instructions\nCollect jump targets\n", count);

	// collect jump targets
	for (i = 0; i < count; i++) {
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) {
			cs_x86_op *op = &(insn[i].detail->x86.operands[0]);
			if (op->type == X86_OP_IMM) {
				DBG_PRINT("@%zu instr adding jump_targets[%zu]=0x%08lx jmp dst\n", i, jt_cnt, op->imm);
				if (prev_instr(op->imm, insn, count)>f->base_address) jump_targets[jt_cnt++]=prev_instr(op->imm, insn, count);
				}
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) {
			DBG_PRINT("@%zu instr adding jump_targets[%zu]=0x%08lx ret\n", i, jt_cnt, next_instr(insn[i].address, insn, count));
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
	for (i = 0; i < count; i++) {
		current->instr_cnt++;
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) DBG_PRINT("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
		DBG_PRINT("[%d] Process instruction at 0x%08lx\n", blk_cnt, insn[i].address);
		not_jmp_targets=not_in(insn[i].address, jump_targets, jt_cnt);
		if (cs_insn_group(handle, &insn[i], CS_GRP_INT)) {
			DBG_PRINT("[%d] Block starting at 0x%08x has syscall\n", blk_cnt, current->start);
			current->syscall=1;
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) {
			DBG_PRINT("[%d] Block starting at 0x%08x has ret\n", blk_cnt, current->start);
			current->ret=1;
			patch_instr(&insn[i], f);
			}
		if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP) || !not_jmp_targets) {
			DBG_PRINT("[%d] Process instruction at 0x%08lx determine if forward or branch needs to be filled\n", blk_cnt, insn[i].address);
//			current->end=i<count-1?insn[i+1].address:f->base_address+f->length;
			current->end=i<count-1?insn[i].address:f->base_address+f->length;
			cs_x86_op *op = &(insn[i].detail->x86.operands[0]);

			if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) {
				DBG_PRINT("[%d] Block ending at 0x%08lx is because a branch statement op->type=%d\n", blk_cnt, insn[i].address, op->type);
				if (op->type == X86_OP_IMM) {
					// Direct jump or call
					DBG_PRINT("[%d] Hit Block termination @0x%08lx set branch_addr=0x%08lx\n", blk_cnt, insn[i].address, op->imm);
					if (insn[i].id != X86_INS_CALL) current->branch_addr=op->imm;
					}
				if (op->type == X86_OP_MEM) {
					// Indirect jump or call
					DBG_PRINT("[%d] Hit Block termination @0x%08lx set branch_addr=0x%08lx\n", blk_cnt, insn[i].address, 1UL);
					if (insn[i].id != X86_INS_CALL) current->branch_addr=1;
					}
				}

			if (i+1 < count) {
				DBG_PRINT("[%d] X86_INS_JMP=%d\n", blk_cnt,X86_INS_JMP);
				DBG_PRINT("[%d] Last instruction for this block at 0x%08lx id=%d, mnemo=%s (insn[i].id != X86_INS_JMP)=%d\n", blk_cnt, insn[i].address, insn[i].id, insn[i].mnemonic, strcmp(insn[i].mnemonic, "jmp"));
				if (strcmp(insn[i].mnemonic, "jmp")) {
					DBG_PRINT("[%d] Hit Block termination @0x%08lx set forward_addr=0x%08lx\n", blk_cnt, insn[i].address, insn[i+1].address);
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
				DBG_PRINT("[%d] A block is just been created: Start=0x%08x, end=0x%08x, sys=%d, ret=%d forward=0x%08x branch=0x%08x, instr_sz=%d\n", 
						blk_cnt, current->start, current->end,  current->syscall, current->ret, current->forward_addr, current->branch_addr, current->instr_cnt);
				blk_cnt++;
				current=app;
				}
			}
		}
	cs_free(insn, count);
	cs_close(&handle);

	DL_FOREACH(first,current) {
		found=false;
		DL_FOREACH(first,app){
			if ((current->branch_addr >= (unsigned int)app->start) && (current->branch_addr < (unsigned int) app->end)) {
				found=true;
				break;
				}
			}
		current->branch = found?app:NULL;

		if (app) DBG_PRINT("link 0x%08x and 0x%08x\n", current->start, app->start); else DBG_PRINT("branch 0x%08x not found\n", current->branch_addr);

		found=false;
		DL_FOREACH(first,app){
			if ((current->forward_addr >= (unsigned int) app->start) && (current->forward_addr < (unsigned int) app->end)) {
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

void dispose_cfg(struct Block *root){
	struct Block *elt, *tmp;

	DL_FOREACH_SAFE(root,elt,tmp) {
		DL_DELETE(root,elt);
		free(elt);
	}

}
