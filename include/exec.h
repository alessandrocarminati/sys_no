#ifndef EXEC_H

#define EXEC_H

#include <unicorn/unicorn.h>
#include "cfg.h"

#define STACK_TOP    0x55aa55aa00008000
#define MEM_SIZE_4KB 0x1000ULL
#define MEM_SIZE_2MB 0x200000ULL

#define SUCCESS	0
#define SYSCALL 1
#define ERR_NO_VALID_CONTEXT 2
#define ERR_EMULATION_START_FAILED 3
#define ERR_CANT_WRITE_TEXT 4
#define ERR_CANT_OPEN_UNICORN 5
#define ERR_CANT_ALLOCATE_TEXT 6
#define ERR_CANT_ALLOCATE_STACK 7

#define SYS_MAX_RES 20

struct sys_results {
	uint64_t addr[SYS_MAX_RES];
	uint32_t sys_no[SYS_MAX_RES];
	int	num;
	};

static bool x86_invert_jump(uint8_t *insn);
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_instruction(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_mem_fetch_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
void dump_registers(uc_engine *uc);
int execute_block(uc_engine *uc, struct Block *b, struct sys_results *sys_res);
int emu_init(unsigned char * code, uint64_t base_address, int size, uc_engine **uc);
void emu_stop(uc_engine *uc);
struct sys_results *init_res(void);
void ins_res(struct sys_results *sys_res, uint64_t addr, uint32_t num);
void print_res(struct sys_results *sys_res, const char *fmt);
void dispose_res(struct sys_results *sys_res, char *buf);

#endif

