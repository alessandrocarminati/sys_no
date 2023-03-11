#include <stdio.h>
#include <unicorn/unicorn.h>

#include "sample_code.h"
#include "cfg.h"
#include "paths.h"
#include "exec.h"
#include "global_defines.h"

int execute_block_seq(struct exec_item *f, struct block_list *b){
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
		err=execute_block(uc, b->blocks_addr[i]);
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


int main(int argc, char *argv[]){
	struct block_list v={.blocks=NULL, .blocks_no=0}, p={.blocks=NULL, .blocks_no=0};
	struct Block *root;
	int i, index, tmp=0;
	uc_engine *uc=NULL;

	if (argc<=1) {
		printf("wrong cmdline\n");
		return 1;
		}
	if ((index=strtol (argv[1],NULL,10))==0) {
		printf("error\n");
		return 1;
		}
	if (index>sizeof(f)+1) {
		printf("index out of range\n");
		return 1;
		}
	printf("function name %s, starting analysis\n", f[index]->name);
	v.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
	p.blocks_addr=(struct Block **) malloc(MAX_BLOCKS*sizeof(uint64_t));

	init_res();
	root=build_cfg(f[index]);
	print_plain_cfg(root);
	printf("%s", cfg2dot(root));
	while (search_next(root, HOST_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
		DBG_PRINT("Path found!\n");
		for (i=0; i<p.blocks_no; i++) {
			printf("0x%08x, ", p.blocks_addr[i]->start);
			}
		printf("\n");
		if (execute_block_seq(f[index], &p)) {
			printf("Premature termination!!!\n");
			break;
			}
		}
	print_res("{address: \"0x%08lx\", number:\"%d\"}\n");
}
