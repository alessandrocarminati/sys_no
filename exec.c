#include <unicorn/unicorn.h>
#include <string.h>
#include <stdint.h>
#include "exec.h"

static bool x86_invert_jump(uint8_t *insn){
	uint16_t x86_j_near[]=
	{0x800F, 0x810F, 0x880F, 0x890F, 0x840F, 0x850F, 0x820F, 0x830F, 0x860F, 0x870F, 0x8C0F, 0x8D0F, 0x8E0F, 0x8F0F, 0x8A0F, 0x8B0F};
	uint8_t x86_j_short[]=
	{0x70, 0x71, 0x78, 0x79, 0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0x7A, 0x7B, 0xe9, 0xe9};
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
		DBG_PRINT(">>> Missing memory is being READ at 0x%08lx data size = %u\n", address, size);
		DBG_PRINT(">>> allocate 64k at 0x%08lx\n", address & 0xffffffffffff0000);
		uc_mem_map(uc, address & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		return true;
	case UC_MEM_WRITE_UNMAPPED:
		DBG_PRINT(">>> Missing memory is being WRITE at 0x%08lx data size = %u, data value = 0x%08lx\n", address, size, value);
		DBG_PRINT(">>> allocate 64k at 0x%08lx\n", address & 0xffffffffffff0000);
		uc_mem_map(uc, address & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		return true;
	}
}

static bool hook_instruction(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	uint64_t pc;
	int i;

	uc_reg_read(uc, UC_X86_REG_RIP, &pc);
	DBG_PRINT("executed 0x%08lx\n", pc);
	return true;
}

static void hook_mem_fetch_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	int i;

	DBG_PRINT("]] read at 0x%08lx\n", address);
}

static void hook_syscall(uc_engine *uc, void *user_data) {
	uint64_t rax, rip;

	uc_reg_read(uc, UC_X86_REG_RAX, &rax);
	uc_reg_read(uc, UC_X86_REG_RIP, &rip);
	printf("############### Syscall [0x%08lx] @0x%08lx ###############\n", rax, rip);
}

void dump_registers(uc_engine *uc){
	uint64_t reg;

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

}
int execute_block(uc_engine *uc, struct Block *b) {
	uc_err err;
	uc_hook trace1, trace2, trace3;
	uint64_t reg;
	uint32_t res;
	int i;

	if (!uc) return ERR_NO_VALID_CONTEXT;

	DBG_PRINT("Settig up hooks on memory unmapped events\n");
	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

	DBG_PRINT("Settig up hooks on syscalls events\n");
	uc_hook_add(uc, &trace2, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);

	DBG_PRINT("Executing block @(0x%08x ~ 0x%08x) [%d instructions]\n", b->start, b->end, b->instr_cnt);
	err = uc_emu_start(uc, b->start, 0, 0, b->instr_cnt);
	if (err) {
		uc_reg_read(uc, UC_X86_REG_RIP, &reg);
		DBG_PRINT("Failed on uc_emu_start() at 0x%08lx with error returned %u: %s\n", reg, err, uc_strerror(err));
		dump_registers(uc);
		return ERR_EMULATION_START_FAILED;
		}
	return b->syscall?SYSCALL:SUCCESS;
}

int emu_init(unsigned char *code, uint64_t base_address, int size, uc_engine **ret) {
	int err;
	uint64_t reg;
	uc_engine *uc;

	DBG_PRINT("initialyzing Unicorn engine\n");
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err) {
		DBG_PRINT("Failed on uc_open() with error returned: %u\n", err);
		return ERR_CANT_OPEN_UNICORN;
		}
	DBG_PRINT("Allocating memory for text application\n");
	// allocate 4kb aligned memory
	if ((err=uc_mem_map(uc, base_address & 0xffffffffffff0000, 1024*1024*2, UC_PROT_ALL))){
		DBG_PRINT("Failed to allocate emulation memory, quit! (%u)\n", err);
		return ERR_CANT_ALLOCATE_TEXT;
		}

	DBG_PRINT("Allocating stack memory\n");
	reg=STACK_TOP;
	uc_reg_write(uc, UC_X86_REG_RSP, &reg);
	if ((err=uc_mem_map(uc, STACK_TOP & 0xffffffffffff0000, 1024*64, UC_PROT_ALL))){
		DBG_PRINT("Failed to allocate stack memory, quit! (%u)\n", err);
		return ERR_CANT_ALLOCATE_TEXT;
		}

	DBG_PRINT("Writing text into memory @0x%08lx\n", base_address);
	if ((err=uc_mem_write(uc, base_address, code, size))) {
		DBG_PRINT("Failed to write emulation code to memory, quit! (%u)\n", err);
		uc_close(uc);
		return ERR_CANT_WRITE_TEXT;
		}
	DBG_PRINT("Initialization complete\n");
	*ret=uc;
	return SUCCESS;
}

void emu_stop(uc_engine *uc){
	uc_close(uc);
}
