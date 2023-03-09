#include <stdio.h>
#include <unicorn/unicorn.h>

#include "sample_code.h"
#include "cfg.h"
#include "paths.h"
#include "exec.h"

int execute_block_seq(struct exec_item *f, struct block_list *b){
	uc_engine *uc;
	int i, err;

	err=emu_init(f->text, f->base_address, f->length, &uc);
	if (err) {
		printf("init failed\n");
		return 1;
		}

	for (i=0; i<b->blocks_no; i++) {
		printf("Execute block #%d, start=0x%08x, end=0x%08x\n",i, b->blocks_addr[i]->start, b->blocks_addr[i]->end);
		err=execute_block(uc, b->blocks_addr[i]);
		printf("%d\n",err);
		if ((err!=SUCCESS)&&(err!=SYSCALL)) {
			printf("exit!\n");
			return 1;
			}
		dump_registers(uc);
		}
	emu_stop(uc);
	return 0;
}


int main(){
	struct block_list v={.blocks=NULL, .blocks_no=0}, p={.blocks=NULL, .blocks_no=0};
	struct Block *root;
	int i, tmp=0;
	uc_engine *uc=NULL;

	v.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
	p.blocks_addr=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));

	root=build_cfg(&f2);
	print_plain_cfg(root);
	printf("%s", cfg2dot(root));
	while (search_next(root, HOST_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
		printf("Path found!\n");
		for (i=0; i<p.blocks_no; i++) {
			printf("0x%08x, ", p.blocks_addr[i]->start);
			}
		printf("\n");
		execute_block_seq(&f2, &p);
		}

}
