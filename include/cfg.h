#ifndef CFG_H

#define CFG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "../include/global_defines.h"

#define MAX_JT		128
#define MAX_BLOCKS	1024
#define DOT_BUF_SIZE	8192
#define NO_ERROR	0
#define ERR_BUFOVF	1
#define ERR_BUFOVF_MSG	"Dot buffer too small"

#define BIN_X86_32	0x01
#define BIN_PPC_32	0x02
#define BIN_MIPS_32	0x03
#define BIN_ARM_32	0x04
#define BIN_X86_64	0x09
#define BIN_PPC_64	0x0a
#define BIN_MIPS_64	0x0b
#define BIN_ARM_64	0x0c

#define BIN_UNKNOWN	0xffffffffU
#define BIN_X86		0x01
#define BIN_PPC		0x02
#define BIN_MIPS	0x03
#define BIN_ARM		0x04

#define BIN_32		0x00
#define BIN_64		0x08
#define BIN_ARCH_MSK	0x07
#define BIN_BITS_MSK	0x08

#define BT_OK		1
#define BT_KO		0

#define BT2CSARCH(bintype) \
	( (bintype == BIN_X86_32) ? CS_ARCH_X86 : \
	  (bintype == BIN_PPC_32) ? CS_ARCH_PPC : \
	  (bintype == BIN_MIPS_32) ? CS_ARCH_MIPS : \
	  (bintype == BIN_ARM_32) ? CS_ARCH_ARM : \
	  (bintype == BIN_X86_64) ? CS_ARCH_X86 : \
	  (bintype == BIN_PPC_64) ? CS_ARCH_PPC : \
	  (bintype == BIN_MIPS_64) ? CS_ARCH_MIPS : \
	  (bintype == BIN_ARM_64) ? CS_ARCH_ARM64 : \
	  BIN_UNKNOWN )
#define BT2CSMODE(bintype) \
	( (bintype == BIN_X86_32) ? CS_MODE_32 : \
	  (bintype == BIN_PPC_32) ? CS_MODE_32 : \
	  (bintype == BIN_MIPS_32) ? CS_MODE_32 : \
	  (bintype == BIN_ARM_32) ? CS_MODE_ARM : \
	  (bintype == BIN_X86_64) ? CS_MODE_64 : \
	  (bintype == BIN_PPC_64) ? CS_MODE_64 : \
	  (bintype == BIN_MIPS_64) ? CS_MODE_64 : \
	  (bintype == BIN_ARM_64) ? CS_MODE_V8 : \
	  BIN_UNKNOWN )

#define BT_SUPPORTED(bintype) (\
	(bintype == BIN_X86_64) ? BT_OK : \
	BT_KO )

#define R2TOBT(arch,bits,os) (\
	(strncmp(arch, "x86", 3)==0) && (bits=64) && (strncmp(os, "linux", 5)==0) ? BIN_X86_64 : \
	BIN_UNKNOWN )

#ifdef DEBUG
#define DBG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DBG_PRINT(...) do {} while (0)
#endif


struct exec_item {
	uint32_t	bin_type;
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

struct Block *build_cfg(struct exec_item *f);
void print_plain_cfg(struct Block *root);
char *cfg2dot(struct Block *root);
bool not_in(uint64_t c, uint64_t visited[], int visited_no);

static int _print_dot(struct Block *current, char *dot, int *dot_len, uint64_t visited[], int *visited_no);
static uint64_t prev_instr(uint64_t curr, cs_insn *insn, int instr_no);
static uint64_t next_instr(uint64_t curr, cs_insn *insn, int instr_no);

#endif

