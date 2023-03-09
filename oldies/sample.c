#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <string.h>
#include <stdint.h>
#include "sample_code.h"

#define STACK_TOP    0x55aa55aa0000fffc


uint16_t x86_j_near[]=
	{0x800F, 0x810F, 0x880F, 0x890F, 0x840F, 0x850F, 0x820F, 0x830F, 0x860F, 0x870F, 0x8C0F, 0x8D0F, 0x8E0F, 0x8F0F, 0x8A0F, 0x8B0F};

uint8_t x86_j_short[]=
	{0x70, 0x71, 0x78, 0x79, 0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0x7A, 0x7B, 0xe9, 0xe9};

struct jmp_idx {
	uint64_t pos[512];
	uint32_t index;
	};

uint64_t prec_pc;
char *coverage_map;
struct jmp_idx func_jmps;

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

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	switch (type) {
	default:
		printf(">>> Missing memory is being READ at 0x%08lx data size = %u\n", address, size);
		printf(">>> allocate 64k at 0x%08lx\n", address & 0xffffffffffff0000);
		uc_mem_map(uc, address & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		return true;
	case UC_MEM_WRITE_UNMAPPED:
		printf(">>> Missing memory is being WRITE at 0x%08lx data size = %u, data value = 0x%08lx\n", address, size, value);
		printf(">>> allocate 64k at 0x%08lx\n", address & 0xffffffffffff0000);
		uc_mem_map(uc, address & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		return true;
	}
}

static bool hook_instruction(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	uint64_t pc;
	int i;

	uc_reg_read(uc, UC_X86_REG_RIP, &pc);
	printf("executed 0x%08lx\n", pc);
	return true;
}
static void  hook_mem_fetch_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	int i;

	printf("]] read at 0x%08lx\n", address);
	if ((address >=BASE_ADDRESS) && (address<=BASE_ADDRESS + sizeof(function) - 1)) {
		for (i=address; i<address+size; i++){
			*(coverage_map+address-BASE_ADDRESS)=1;
			}
		}
}

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
	uint64_t pc,i;
	csh handle;
	cs_insn *insn;
	size_t count;

	if (((address >= BASE_ADDRESS) && (address <= BASE_ADDRESS + sizeof(function) - 1))) {
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) uc_emu_stop(uc);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		count = cs_disasm(handle, (uint8_t *) (function+(address-BASE_ADDRESS)), size, address, 0, &insn);
		if (count > 0) {
			size_t j;
			for (j = 0; j < count; j++) {
//				printf("0x%08lx\n",insn[j].detail);
				printf("0x%"PRIx64":\t%s\t\t%s grp:%d,%d,%d,%d\n", insn[j].address, insn[j].mnemonic, insn[j].op_str, 
					insn[j].detail->groups[0],
					insn[j].detail->groups[1],
					insn[j].detail->groups[2],
					insn[j].detail->groups[3]
					);
				}
			cs_free(insn, count);
			}
		cs_close(&handle);
		uc_reg_read(uc, UC_X86_REG_RIP, &pc);
		printf("block at 0x%08lx size=0x%x   [current pc=0x%08lx]\n", address, size, pc);
		if ((address >= BASE_ADDRESS) && (address <= BASE_ADDRESS + sizeof(function) - 1)) {
			for (i=address; i<address+size; i++) *(coverage_map+i-BASE_ADDRESS)=1;
			}
		} else uc_emu_stop(uc);

}

bool is_type(cs_detail *detail, cs_group_type t){
	int i;
	bool res= false;

	for (i=0; i<detail->groups_count;i++) res|=(detail->groups[i]==t);
	return res;
}

int main(int argc, char **argv, char **envp) {
	uc_engine *uc;
	uc_err err;
	uc_hook trace1, trace2, trace3;
	uint64_t reg;
	int i;
	bool started=false;
	csh handle;
	cs_insn *insn;
	size_t count;

	printf("===================================\n");
	printf("scanning the function code and build the jump map\n");

	func_jmps.index=0;
	func_jmps.pos[func_jmps.index++]=0; // first skip
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return -1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, (uint8_t *) function, sizeof(function), BASE_ADDRESS, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
//			printf("0x%"PRIx64":\t%s\t\t%-40s\tgrp[%d]:%-3d,%-3d,%-3d,%-3d\n", insn[j].address, insn[j].mnemonic, insn[j].op_str, 
//				insn[j].detail->groups_count,
//				insn[j].detail->groups[0],
//				insn[j].detail->groups[1],
//				insn[j].detail->groups[2],
//				insn[j].detail->groups[3]
//				);

			printf("0x%"PRIx64":\t%s\t\t%-40s\t%-10s\t%-10s\t%-10s\t%-10s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str, 
				is_type(insn[j].detail, CS_GRP_JUMP)?"JMP":"NO_JMP",
				is_type(insn[j].detail, CS_GRP_CALL)?"CALL":"NO_CALL",
				is_type(insn[j].detail, CS_GRP_INT)?"INT":"NO_INT",
				is_type(insn[j].detail, CS_GRP_RET)?"RET":"NO_RET"
				);

			if (is_type(insn[j].detail, CS_GRP_JUMP)) func_jmps.pos[func_jmps.index++]=insn[j].address;
			}

		cs_free(insn, count);
		}
	cs_close(&handle);

	printf("initializing coverage map\n");
	coverage_map =(char *)malloc(sizeof(function));
	memset(coverage_map, 0, sizeof(function));

	for (int j=0; j<5; j++){

		if (func_jmps.pos[j]!=0) {
			printf("patching function at 0x%08lx \n",func_jmps.pos[j]);
			printf("offset = 0x%08lx \n",func_jmps.pos[j]-BASE_ADDRESS);
			printf("address func = 0x%08lx \n",&function);
			printf("patch address = 0x%08lx \n",((uint8_t *)&function)+func_jmps.pos[j]-BASE_ADDRESS);


			x86_invert_jump(((uint8_t *)&function)+func_jmps.pos[j]-BASE_ADDRESS);
			}

		err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
		if (err) {
			printf("Failed on uc_open() with error returned: %u\n", err);
			return 1;
			}
		printf("2MB allocating at 0x%08x to host the code\n", BASE_ADDRESS&(4*1024-1));
		uc_mem_map(uc, 0x000a0000, 2 * 1024 * 1024, UC_PROT_ALL);

		// allocate 64k stack
		printf("64KB allocating at 0x%08lx and set stack register at 0x%08lx\n", STACK_TOP & 0xffffffffffff0000, STACK_TOP);
		uc_mem_map(uc, STACK_TOP & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		reg=STACK_TOP;
		uc_reg_write(uc, UC_X86_REG_RSP, &reg);

		printf("writing function at 0x%08x for %ld bytes\n", BASE_ADDRESS,sizeof(function));
		if (uc_mem_write(uc, BASE_ADDRESS, function, sizeof(function))) {
			printf("Failed to write emulation code to memory, quit!\n");
			return 1;
			}

		printf("Add hook on memory unmapped events\n");
		uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

//	printf("Add hook on single instruction\n");
//	err=uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_instruction, NULL, 1, 0);
//	printf("UC_HOOK_CODE, -> %d\n", err);
//	err=uc_hook_add(uc, &trace3, UC_HOOK_MEM_READ, hook_mem_fetch_check, NULL, BASE_ADDRESS, BASE_ADDRESS + sizeof(function) - 1);
//	printf("UC_HOOK_MEM_READ -> %d\n", err);

		uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

		err = uc_emu_start(uc, BASE_ADDRESS, BASE_ADDRESS + sizeof(function) - 1, 0, 0);
		if (err) {
			printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
			}

		printf(">>> Emulation done. Below is the CPU context\n");


		for (i=0; i<sizeof(function) - 1; i++) printf("%d", *(coverage_map+i));
		printf("\n");
		}

	uc_reg_read(uc, UC_X86_REG_RAX, &reg);
	printf(">>> RAX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RBX, &reg);
	printf(">>> RBX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RCX, &reg);
	printf(">>> RCX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RDX, &reg);
	printf(">>> RDX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RSI, &reg);
	printf(">>> RSI = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RDI, &reg);
	printf(">>> RDI = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R8, &reg);
	printf(">>> R8 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R9, &reg);
	printf(">>> R9 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R10, &reg);
	printf(">>> R10 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R11, &reg);
	printf(">>> R11 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R12, &reg);
	printf(">>> R12 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R13, &reg);
	printf(">>> R13 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R14, &reg);
	printf(">>> R14 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R15, &reg);
	printf(">>> R15 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RSP, &reg);
	printf(">>> RSP = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RIP, &reg);
	printf(">>> RIP = 0x%lx\n", reg);
	printf("code coverage map\n");
	for (i=0; i<func_jmps.index - 1; i++) printf("0x%08lx, ", func_jmps.pos[i]);
	printf("\ncnt:%d\n", func_jmps.index);


	uc_close(uc);
}
