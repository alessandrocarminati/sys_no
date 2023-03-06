#ifndef PATHS_H

#define PATHS_H

#include "cfg.h"

#define NEW_FOUND	1
#define NO_FOUND 	0

int search_next(struct Block *current, struct block_list *visited, struct block_list *path, int path_len, int *itn_no);

#endif

