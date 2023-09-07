#ifndef CFG_H

#define CFG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "../include/global_defines.h"

#define MAX_JT			(4096 * 16)
#define MAX_CALL_PATCH_CNT	64
#define MAX_BLOCKS		1024
#define DOT_BUF_SIZE		8192
#define NO_ERROR		0
#define ERR_BUFOVF		1
#define ERR_BUFOVF_MSG		"Dot buffer too small"

#ifdef DEBUG
#define DBG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DBG_PRINT(...) do {} while (0)
#endif


struct exec_item {
	uint64_t	base_address;
	uint32_t	length;
	unsigned char 	*text;
#ifdef DEMO
	char 		*disass;
	char		*name;
#endif
};


struct Block {
	int 		start;
	int 		end;
	int		instr_cnt;
	unsigned int 	syscall : 1;
	unsigned int 	ret : 1;
	struct 		Block *branch, *forward, *next, *prev;
	uint32_t 	branch_addr, forward_addr;
};

struct block_list {
	union {
		uint64_t *blocks;
		struct Block **blocks_addr;
		};

	int     blocks_no;
};

void patch_syscall_at(struct exec_item *f, uint64_t addr);
void patch_calls(struct exec_item *f);
struct Block *build_cfg(struct exec_item *f);
void print_plain_cfg(struct Block *root);
char *cfg2dot(struct Block *root);
bool not_in(uint64_t c, uint64_t visited[], int visited_no);

static int _print_dot(struct Block *current, char *dot, int *dot_len, uint64_t visited[], int *visited_no);
static uint64_t prev_instr(uint64_t curr, cs_insn *insn, int instr_no);
static uint64_t next_instr(uint64_t curr, cs_insn *insn, int instr_no);

#endif

