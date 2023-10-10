#include <r_core.h>
#include <r_anal.h>
#include <string.h>
#include "../include/cfg.h"
#include "../include/paths.h"
#include "../include/exec.h"
#include "../include/global_defines.h"
#include "../include/ansi_term.h"
#include "r2pi_sysno.h"


static int execute_block_seq(struct exec_item *f, struct block_list *b, struct sys_results *sys_res){
	uc_engine *uc;
	int i, err;

	err=emu_init(f->text, f->base_address, f->length, &uc);
	if (err) return 1;

	for (i=0; i<b->blocks_no; i++) {
		DBG_PRINT(">>>>>>>>>>>>>>>>>>> Execution #%02d start <<<<<<<<<<<<<<<<<<<\n",i);
		DBG_PRINT("Execute block #%d, start=0x%08x, end=0x%08x\n",i, b->blocks_addr[i]->start, b->blocks_addr[i]->end);
		err=execute_block(uc, b->blocks_addr[i], sys_res);
		if ((err!=SUCCESS)&&(err!=SYSCALL)) return 1;
		DBG_PRINT(">>>>>>>>>>>>>>>>>>> Execution #%02d end <<<<<<<<<<<<<<<<<<<\n",i);
		}
	emu_stop(uc);
	return 0;
}

static struct Block *find_block_from_addr(struct Block *root, int addr){
	struct Block *tmp = root;

	while ((tmp) && (tmp->start != addr)) {
		tmp=tmp->next;
	}
	return tmp;
}

static int execute_single_block(struct exec_item *f, struct Block *b, struct sys_results *sys_res){
	uc_engine *uc;
	int err;

	err=emu_init(f->text, f->base_address, f->length, &uc);
	if (err) return 1;
	err=execute_block(uc, b, sys_res);
	if (err!=SYSCALL) return 0;
	emu_stop(uc);
	return 1;
}



static int do_sysno(void* user, const char* cmd) {
	int n;
	char *args[7];

	if (strncmp("sysno", cmd, 5)==0) {
		n=PROC_CMD_PARSE(cmd, args);
		if ((n<1)|| (n>2)) {
			eprintf (BRED "[*]" RED "%s: syntax error!\n" CRESET, PLUGIN_NAME);
			return true;
			}
		eprintf(BGRN "[*]" GRN " %s is starting computation\n", args[0]?args[0]:"pi");
		RCore *core = (RCore *) user;
		RAnalFunction *func = r_anal_get_fcn_in(core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
		if (!func) {
			eprintf (BRED "[*]" RED "no anal data, please run analysis before calling this\n" CRESET);
			return true;
			}
		ut64 fcnlsize = r_anal_function_linear_size(func);
		struct exec_item f = {};
		f.base_address=core->offset;
		f.length=fcnlsize;
		f.text=malloc(f.length);
		if (r_io_read_at (core->io, f.base_address, f.text, f.length) ) {
			struct block_list v={.blocks=NULL, .blocks_no=0}, p={.blocks=NULL, .blocks_no=0};
			struct Block *root;
			int tmp=0;
			struct sys_results *sys_res;
			char *buf = NULL;

			v.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
			p.blocks_addr=(struct Block **) malloc(MAX_BLOCKS*sizeof(uint64_t));
			sys_res=init_res();
			if (!sys_res) {
				dispose_res(sys_res, buf);
				free(v.blocks);
				free(p.blocks);
				}
			DBG_PRINT("before\n");
			DBG_PRINT_HEX_TEXT(&f);
			patch_calls(&f);
			DBG_PRINT("before\n");
			DBG_PRINT_HEX_TEXT(&f);
			if ((root=build_cfg(&f))) {
#ifdef DEBUG
				char *tmp_buf;
				tmp_buf=cfg2dot(root);
				DBG_PRINT("%s", tmp_buf);
				free(tmp_buf);
#endif
				if (root == NULL) {
					eprintf(BRED "[*]" RED " Function disassembly failed!!!\n" CRESET);
				}
				else {
					eprintf(BGRN "[*]" GRN " Generating cfg for the given function\n" CRESET);
					while (search_next(root, HOST_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
						eprintf(BGRN "[*]" GRN " checking a path\n" CRESET);
						for (int i=0; i<p.blocks_no; i++) {
							eprintf(YEL "0x%08x,", p.blocks_addr[i]->start);
						}
						eprintf("\n" CRESET);
						if (execute_block_seq(&f, &p, sys_res)) {
							eprintf(BRED "[*]" RED " Premature termination!!!\n" CRESET);
							free(v.blocks);
							free(p.blocks);
							dispose_cfg(root);
							dispose_res(sys_res, buf);
							break;
						}
						if (sys_res->num>0)
							patch_syscall_at(&f, sys_res->addr[sys_res->num - 1]);
					}
					eprintf(BYEL "[*]" YEL " Syscall found are %d, cfg results are %d, there are %d still to figure out.!!!\n" CRESET, f.syscalls, sys_res->num, f.syscalls - sys_res->num);

					for (unsigned int i=0; i<f.syscalls; i++){
						eprintf(BYEL "[*]" YEL " %s block at 0x%08lx syscall at 0x%08lx is %s\n" CRESET, 
							f.syscall_map[i].used?"Skip":"Process", f.syscall_map[i].blk_address, f.syscall_map[i].sys_address, f.syscall_map[i].used?"known":"unknown");
						if (!f.syscall_map[i].used) {
							int found = execute_single_block(&f, find_block_from_addr(root, f.syscall_map[i].blk_address), sys_res);
							printf("%s", found?BGRN "[*]" GRN " New syscall number!\n" CRESET:BRED "[*]" RED " no luck!!!\n" CRESET);
						}
					}

					buf=print_res(sys_res, "{address: \"0x%08lx\", number:\"%d\"}");
					eprintf(BGRN "[*]" GRN " Results:\n" CRESET);
					eprintf("%s\n", buf);
				}
				free(v.blocks);
				free(p.blocks);
				dispose_cfg(root);
				dispose_res(sys_res, buf);
			} else {
				eprintf(BRED "[*]" RED " Analysis failed due to an error!\n" CRESET);
				free(v.blocks);
				free(p.blocks);
				dispose_cfg(root);
				dispose_res(sys_res, buf);
			}

		}
		eprintf("\n");
		free(f.text);
		return true;
		}
	return false;
}

RCorePlugin core_plugin_desc = {
	.name = "Syscall Unicorn",
	.desc = "It provides syscall numbers used in the current function",
	.license = "MIT",
	.author = AUTHOR,
	.version = "0.0.1",
	.call = do_sysno,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &core_plugin_desc,
	.version = R2_VERSION
};
#endif
