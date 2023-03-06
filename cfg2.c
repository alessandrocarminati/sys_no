#include <stdio.h>

#include "sample_code.h"
#include "cfg.h"
#include "paths.h"

int main(){
	struct  block_list v={.blocks=NULL, .blocks_no=0}, p={.blocks=NULL, .blocks_no=0};
	struct Block *root;
	int i, tmp=0;

	v.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
	p.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));

	root=build_cfg(&f1);
	print_plain_cfg(root);
	printf("%s", cfg2dot(root));
	while (search_next(root, VIRTUAL_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
		printf("Path found!\n");
		for (i=0; i<p.blocks_no; i++) {
			printf("0x%08lx, ", *(p.blocks+i));
			}
		printf("\n");

//		for (i=0; i<v.blocks_no; i++) {printf("0x%08lx, ", *(v.blocks+i));}printf("\n");
		}
}
