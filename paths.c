#include "cfg.h"
#include "paths.h"


int search_next(struct Block *current, int res_type, struct block_list *visited, struct block_list *path, int path_len, int *itn_no) {

	visited->blocks[(visited->blocks_no)++]=current->start;
	if (res_type==VIRTUAL_ADDRESS) path->blocks     [(path_len)++]=current->start;
	if (res_type==HOST_ADDRESS)    path->blocks_addr[(path_len)++]=current;

	if ((*(itn_no)<visited->blocks_no)&&(current->syscall)) {
		path->blocks_no=path_len;
		*(itn_no)=visited->blocks_no;
		visited->blocks_no=0;
		return NEW_FOUND;
		}

	if ((current->forward) && not_in(current->forward->start, visited->blocks, visited->blocks_no) && (search_next(current->forward, res_type, visited, path, path_len, itn_no)==NEW_FOUND)) {
		return NEW_FOUND;
		}

	if ((current->branch) && not_in(current->branch->start, visited->blocks, visited->blocks_no) && (search_next(current->branch, res_type, visited, path, path_len, itn_no)==NEW_FOUND)) {
		return NEW_FOUND;
		}

	return NO_FOUND;
}


