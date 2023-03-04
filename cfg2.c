#include <stdio.h>

#include "sample_code.h"
#include "cfg.h"

int main(){
	struct Block *root;
	root=build_cfg(&f2);
	print_plain_cfg(root);
	printf("%s", cfg2dot(root));
}
