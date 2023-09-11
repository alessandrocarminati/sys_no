#include <stdio.h>
#include <unicorn/unicorn.h>

#include "../include/cfg.h"
#include "../include/paths.h"
#include "../include/exec.h"
#include "../include/global_defines.h"
#include "../include/ansi_term.h"
#include "sample_code.h"
#include "fp.h"

int execute_block_seq(struct exec_item *f, struct block_list *b, struct sys_results *sys_res){
	uc_engine *uc;
	int i, err;

	err=emu_init(f->text, f->base_address, f->length, &uc);
	if (err) {
		printf("init failed\n");
		return 1;
		}

	for (i=0; i<b->blocks_no; i++) {
		DBG_PRINT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Execution #%02d start <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n", i);
		DBG_PRINT("Execute block #%d, start=0x%08x, end=0x%08x\n",i, b->blocks_addr[i]->start, b->blocks_addr[i]->end);
		err=execute_block(uc, b->blocks_addr[i], sys_res);
		DBG_PRINT("Execution error flag=%d\n",err);
		if ((err!=SUCCESS)&&(err!=SYSCALL)) {
			printf("exit!\n");
			return 1;
			}
#ifdef DEBUG
		dump_registers(uc);
#endif
		DBG_PRINT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Execution #%02d end <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n", i);
		}
	emu_stop(uc);
	return 0;
}

static void print_help(const char *exec_name){
	int i;

	printf(YEL "type: \"%s n\"\nwhere n is one of the followings:\n" reset, exec_name);
	for (i=1; i<=sizeof(f)/8-1; i++) printf("%d\t%s\n", i, f[i]->name);
}

int main(int argc, char *argv[]){
	struct block_list v={.blocks=NULL, .blocks_no=0}, p={.blocks=NULL, .blocks_no=0};
	struct Block *root;
	int i, index, tmp=0;
	struct sys_results *sys_res;
	char *buf, *tmp2;

	if (argc<=1) {
		print_help(argv[0]);
		return 1;
		}
	if ((index=strtol (argv[1],NULL,10))==0) {
		print_help(argv[0]);
		return 1;
		}
	if (index>sizeof(f)/8) {
		printf(BRED "[*]" RED " index out of range\n" reset);
		return 1;
		}
	printf(BGRN "[*]" GRN " Function name "HYEL"%s"GRN", presenting text and starting analysis\n" reset, f[index]->name);
	print_text_file(f[index]->disass);
	printf(BGRN "[*]" GRN " Block statistics:\n" reset);
	v.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
	p.blocks_addr=(struct Block **) malloc(MAX_BLOCKS*sizeof(uint64_t));

	sys_res=init_res();
	root=build_cfg(f[index]);
	print_plain_cfg(root);
	printf(BGRN "[*]" GRN " Generating cfg for the given function\n" reset);
	tmp2=cfg2dot(root);
	printf("%s", tmp2);
	free(tmp2);
	printf(BGRN "[*]" GRN " Generating paths from entry point to the syscalls\n" reset);
	while (search_next(root, HOST_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
		DBG_PRINT(BRED "[*]" RED " Path found!\n");
		for (i=0; i<p.blocks_no; i++) {
			printf("0x%08x, ", p.blocks_addr[i]->start);
			}
		printf("\n");
		if (execute_block_seq(f[index], &p, sys_res)) {
			printf(BRED "[*]" RED " Premature termination!!!\n" reset);
			break;
			}
		}
	printf(BGRN "[*]" GRN " Results from guided execution:\n" reset);
	buf=print_res(sys_res, "{address: \"0x%08lx\", number:\"%d\"}\n");
	printf("%s\n", buf);
	free(v.blocks);
	free(p.blocks);
	dispose_cfg(root);
	dispose_res(sys_res, buf);
}
