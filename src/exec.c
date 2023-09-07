#include <unicorn/unicorn.h>
#include <string.h>
#include <stdint.h>
#include "../include/exec.h"
#include "../include/helper.h"
#include "../include/global_defines.h"

void (*dump_cpu[])(uc_engine *uc) = {
	NULL, 			// 0x00 - invalid
	NULL, 			// 0x01 - BIN_X86_32
	NULL, 			// 0x02 - BIN_PPC_32
	NULL, 			// 0x03 - BIN_MIPS_32
	NULL, 			// 0x04 - BIN_ARM_32
	NULL, 			// 0x05 - Not allocated
	NULL, 			// 0x06 - Not allocated
	NULL, 			// 0x07 - Not allocated
	NULL, 			// 0x08 - Not allocated
	&dump_registers_x86_64,	// 0x09 - BIN_X86_64
	NULL,			// 0x0a - BIN_PPC_64
	NULL,			// 0x0b - BIN_MIPS_64
	dump_registers_aarch64,	// 0x0c - BIN_ARM_64
	NULL,			// 0x0d - Not allocated
	NULL,			// 0x0e - Not allocated
	NULL, 			// 0x0f - Not allocated
};

static bool x86_invert_jump(uint8_t *insn) {
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
	struct exec_item *f=(struct exec_item *)user_data;

	switch (type) {
	default:
		DBG_PRINT(">>> Missing memory is being READ at 0x%08lx data size = %u\n", address, size);
		DBG_PRINT(">>> allocate 64k at 0x%08lx\n", address & ALIGN64K(f->bin_type));
		uc_mem_map(uc, address & ALIGN64K(f->bin_type), 64 * 1024, UC_PROT_ALL);
		return true;
	case UC_MEM_WRITE_UNMAPPED:
		DBG_PRINT(">>> Missing memory is being WRITE at 0x%08lx data size = %u, data value = 0x%08lx\n", address, size, value);
		DBG_PRINT(">>> allocate 64k at 0x%08lx\n", address & ALIGN64K(f->bin_type));
		uc_mem_map(uc, address & ALIGN64K(f->bin_type), 64 * 1024, UC_PROT_ALL);
		return true;
	}
}

static bool hook_instruction(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	uint64_t addr;
	int i;

	struct exec_item *f=(struct exec_item *)user_data;
	uc_reg_read(uc, ARCH_PC_REG(f->bin_type), &addr);
	DBG_PRINT("executed 0x%08lx\n", addr);
	return true;
}

static void hook_mem_fetch_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	int i;

	DBG_PRINT("]] read at 0x%08lx\n", address);
}

static void hook_syscall(uc_engine *uc, void *user_data) {
	uint64_t num, addr;
	struct exec_item *f=(struct exec_item *)user_data;

	uc_reg_read(uc, ARCH_SYSNO_REG(f->bin_type), &num);
	uc_reg_read(uc, ARCH_PC_REG(f->bin_type), &addr);
	ins_res((struct sys_results *)f->user_data, addr, num);
	DBG_PRINT("############### Syscall [0x%08lx] @0x%08lx ###############\n", num, addr);
	print_trace();
}

void dump_registers_x86_64(uc_engine *uc){
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
int execute_block(uc_engine *uc, struct exec_item *f, struct Block *b, struct sys_results *sys_res) {
	uc_err err;
	uc_hook trace1, trace2, trace3;
	uint64_t reg;
	uint32_t res;
	int i;

	if (!uc) return ERR_NO_VALID_CONTEXT;
	f->user_data=(void *)sys_res;

	DBG_PRINT("Settig up hooks on memory unmapped events\n");
	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, f, 1, 0);

	DBG_PRINT("Settig up hooks on syscalls events\n");
	uc_hook_add(uc, &trace2, UC_HOOK_INSN, hook_syscall, f, 1, 0, UC_X86_INS_SYSCALL);

	DBG_PRINT("Executing block @(0x%08x ~ 0x%08x) [%d instructions]\n", b->start, b->end, b->instr_cnt);
	err = uc_emu_start(uc, b->start, 0, 0, b->instr_cnt);
	if (err) {
		uc_reg_read(uc, UC_X86_REG_RIP, &reg);
		DBG_PRINT("Failed on uc_emu_start() at 0x%08lx with error returned %u: %s\n", reg, err, uc_strerror(err));
		if (dump_cpu[f->bin_type]) dump_cpu[f->bin_type](uc);
		return ERR_EMULATION_START_FAILED;
		}
	return b->syscall?SYSCALL:SUCCESS;
}

int emu_init(struct exec_item *f, uc_engine **ret) {
	int err;
	uint64_t reg;
	uc_engine *uc;

	DBG_PRINT("initialyzing Unicorn engine (%d, %d)\n", BT2UCARCH(f->bin_type), BT2UCMODE(f->bin_type));
	err = uc_open(BT2UCARCH(f->bin_type), BT2UCMODE(f->bin_type), &uc);
	if (err) {
		DBG_PRINT("Failed on uc_open() with error returned: %u\n", err);
		return ERR_CANT_OPEN_UNICORN;
		}
	DBG_PRINT("Allocating memory for text application (%p, 0x%08lx & 0x%08lx, %d, %d)\n", uc, f->base_address, ALIGN64K(f->bin_type), 1024*1024*2, UC_PROT_ALL);
	// allocate 4kb aligned memory
	if ((err=uc_mem_map(uc, f->base_address & ALIGN64K(f->bin_type), 1024*1024*2, UC_PROT_ALL))){
		DBG_PRINT("Failed to allocate emulation memory, quit! (%u)\n", err);
		return ERR_CANT_ALLOCATE_TEXT;
		}

	DBG_PRINT("Allocating stack memory (%p, %d, %p)\n", uc, ARCH_SP_REG(f->bin_type), &reg);
	reg=STACK_TOP;
	uc_reg_write(uc, ARCH_SP_REG(f->bin_type), &reg);
	if ((err=uc_mem_map(uc, STACK_TOP & ALIGN64K(f->bin_type), 1024*64, UC_PROT_ALL))){
		DBG_PRINT("Failed to allocate stack memory, quit! (%u)\n", err);
		return ERR_CANT_ALLOCATE_TEXT;
		}

	DBG_PRINT("Writing text into memory @0x%08lx\n", f->base_address);
	if ((err=uc_mem_write(uc, f->base_address, f->text, f->length))) {
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

struct sys_results *init_res(void){
	void *sys_res = malloc(sizeof(struct sys_results));;
        memset(sys_res, 0, sizeof(struct sys_results));
	return (struct sys_results *) sys_res;
}

void ins_res(struct sys_results *sys_res, uint64_t addr, uint32_t num){
	int i=0;
	bool present=false;

	while (i<sys_res->num) {
		if (sys_res->addr[i]==addr) {
			present=true;
			}
		i++;
		}
	if (!present) {
		sys_res->addr[i]=addr;
		sys_res->sys_no[i]=num;
		sys_res->num++;
		}
}
char *print_res(struct sys_results *sys_res, const char *fmt){
	int i=0, offset=0;
	char *buf;

	buf=(char *)malloc(RES_SIZE);
	memset(buf, 0, RES_SIZE);
	for (i=0; i<sys_res->num; i++) {
		offset+=sprintf((buf+offset), fmt, sys_res->addr[i], sys_res->sys_no[i]);
		}
	return buf;
}
void dispose_res(struct sys_results *sys_res, char *buf){
	free(sys_res);
	free(buf);
}
void dump_registers(uc_engine *uc, struct exec_item *f){
	dump_cpu[f->bin_type](uc);
}
void dump_registers_aarch64(uc_engine *uc){
	uint64_t reg;

	uc_reg_read(uc, UC_ARM64_REG_X0, &reg);
	printf(">>> X00 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X1, &reg);
	printf(">>> X01 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X2, &reg);
	printf(">>> X02 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X3, &reg);
	printf(">>> X03 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X4, &reg);
	printf(">>> X04 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X5, &reg);
	printf(">>> X05 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X6, &reg);
	printf(">>> X06 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X7, &reg);
	printf(">>> X07 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X8, &reg);
	printf(">>> X08 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X9, &reg);
	printf(">>> X09 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X10, &reg);
	printf(">>> X10 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X11, &reg);
	printf(">>> X11 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X12, &reg);
	printf(">>> X12 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X13, &reg);
	printf(">>> X13 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X14, &reg);
	printf(">>> X14 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X15, &reg);
	printf(">>> X15 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X16, &reg);
	printf(">>> X16 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X17, &reg);
	printf(">>> X17 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X18, &reg);
	printf(">>> X18 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X19, &reg);
	printf(">>> X19 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X20, &reg);
	printf(">>> X20 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X21, &reg);
	printf(">>> X21 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X22, &reg);
	printf(">>> X22 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X23, &reg);
	printf(">>> X23 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X24, &reg);
	printf(">>> X24 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X25, &reg);
	printf(">>> X25 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X26, &reg);
	printf(">>> X26 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X27, &reg);
	printf(">>> X27 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X28, &reg);
	printf(">>> X28 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X29, &reg);
	printf(">>> X29(FP) = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_X30, &reg);
	printf(">>> X30(LR) = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_SP, &reg);
	printf(">>> SP = 0x%lx\n", reg);
	uc_reg_read(uc, UC_ARM64_REG_PC, &reg);
	printf(">>> PC = 0x%lx\n", reg);
}
