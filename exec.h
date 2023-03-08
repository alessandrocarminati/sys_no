#ifndef EXEC_H

#define EXEC_H

#include <unicorn/unicorn.h>
#include "cfg.h"

#define STACK_TOP    0x55aa55aa0000fff8
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
static bool x86_invert_jump(uint8_t *insn);
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static bool hook_instruction(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void hook_mem_fetch_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
void dump_registers(uc_engine *uc);
int execute_block(uc_engine *uc, struct Block *b);
int emu_init(char * code, uint64_t base_address, int size, uc_engine **uc);
void emu_stop(uc_engine *uc);

#endif

