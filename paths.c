#include "cfg.h"
#include "paths.h"

/*
static bool not_in2(uint64_t c, uint64_t visited[], int visited_no){
        int i;
	printf("not_in2, 0x%08lx\n", c);
        for (i=0; i<visited_no; i++) {
                if (visited[i]== c) return false;
                }
        return true;
}
*/


int search_next(struct Block *current, struct block_list *visited, struct block_list *path, int path_len, int *itn_no) {

	visited->blocks[(visited->blocks_no)++]=current->start;
	path->blocks[(path_len)++]=current->start;
//	*(itn_no)++;

	if ((*(itn_no)<visited->blocks_no)&&(current->syscall)) {
		path->blocks_no=path_len;
		*(itn_no)=visited->blocks_no;
		visited->blocks_no=0;
		return NEW_FOUND;
		}

	if ((current->forward) && not_in(current->forward->start, visited->blocks, visited->blocks_no) && (search_next(current->forward, visited, path, path_len, itn_no)==NEW_FOUND)) {
		return NEW_FOUND;
		}

	if ((current->branch) && not_in(current->branch->start, visited->blocks, visited->blocks_no) && (search_next(current->branch, visited, path, path_len, itn_no)==NEW_FOUND)) {
		return NEW_FOUND;
		}

	return NO_FOUND;
}


/*
int blockpath2syscall(struct Block *current, uint64_t *visited, uint64_t *path, int max_path) {

	//invalidate any preexisting path
	memset(path, 0, max_path*sizeof(uint64_t);
	memset(visited, 0, max_path*sizeof(uint64_t);

	gosearch(current, explored, path, max_path, 0
}
*/
