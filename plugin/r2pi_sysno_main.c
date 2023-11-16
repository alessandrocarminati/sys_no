#include <rz_core.h>
#include <rz_analysis.h>
#include <string.h>
#include "../include/cfg.h"
#include "../include/paths.h"
#include "../include/exec.h"
#include "../include/global_defines.h"
#include "../include/ansi_term.h"
#include "r2pi_sysno.h"


static const RzCmdDescArg sysno_args[] = {
	{ 0 },
};

static const RzCmdDescHelp sysno_help = {
	.summary = "uses capstone and unicorn to find syscalls in current function",
	.args = sysno_args,
};

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
/*
RAnalFunction *r_anal_fcn_find_name(RAnal *anal, const char *name) {
	RAnalFunction *fcn = NULL;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!strcmp (name, fcn->name)) {
			return fcn;
			}
		}
	return NULL;
}
*/
static RzCmdStatus do_sysno(RzCore* core, int argc, const char **argv) {
//	eprintf(BGRN "[*]" GRN " sysno is starting computation\n");
	RzAnalysisFunction *func = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!func) {
//		eprintf (BRED "[*]" RED "no anal data, please run analysis before calling this\n" CRESET);
		return RZ_CMD_STATUS_OK;
		}
//	glibc has this nice function that does not return. Because of that, it need to be handled as a ret
	RzAnalysisFunction *__libc_fatal = rz_analysis_get_function_byname(core->analysis, "sym.__libc_fatal");
	if (__libc_fatal == NULL) {
		//eprintf (BRED "[*]" RED "Can't find __libc_fatal. Is this file a glibc?\n" CRESET);
		return true;
		}
//	eprintf(BGRN "[*]" GRN " __libc_fatal is at 0x%08llx \n", __libc_fatal->addr);
	ut64 fcnlsize = rz_analysis_function_linear_size(func);
	struct exec_item f = {};
	f.base_address=core->offset;
	f.length=fcnlsize;
	f.text=malloc(f.length);
	if (rz_io_read_at (core->io, f.base_address, f.text, f.length) ) {
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
		patch_calls(&f, __libc_fatal->addr);
		DBG_PRINT("after\n");
		DBG_PRINT_HEX_TEXT(&f);
		if ((root=build_cfg(&f))) {
#ifdef DEBUG
			char *tmp_buf;
			tmp_buf=cfg2dot(root);
			DBG_PRINT("%s", tmp_buf);
			free(tmp_buf);
#endif
			if (root == NULL) {
//				eprintf(BRED "[*]" RED " Function disassembly failed!!!\n" CRESET);
				return RZ_CMD_STATUS_OK;
			}
			else {
				//eprintf(BGRN "[*]" GRN " Generating cfg for the given function\n" CRESET);
				while (search_next(root, HOST_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
//					eprintf(BGRN "[*]" GRN " checking a path\n" CRESET);
//					for (int i=0; i<p.blocks_no; i++) {
//						eprintf(YEL "0x%08x,", p.blocks_addr[i]->start);
//					}
//					eprintf("\n" CRESET);
					if (execute_block_seq(&f, &p, sys_res)) {
//						eprintf(BRED "[*]" RED " Premature termination!!!\n" CRESET);
						free(v.blocks);
						free(p.blocks);
						dispose_cfg(root);
						dispose_res(sys_res, buf);
						break;
					}
					if (sys_res->num>0)
						patch_syscall_at(&f, sys_res->addr[sys_res->num - 1]);
				}
//				eprintf(BYEL "[*]" YEL " Syscall found are %d, cfg results are %d, there are %d still to figure out.!!!\n" CRESET, f.syscalls, sys_res->num, f.syscalls - sys_res->num);

				for (unsigned int i=0; i<f.syscalls; i++){
//					eprintf(BYEL "[*]" YEL " %s block at 0x%08lx syscall at 0x%08lx is %s\n" CRESET, 
//						f.syscall_map[i].used?"Skip":"Process", f.syscall_map[i].blk_address, f.syscall_map[i].sys_address, f.syscall_map[i].used?"known":"unknown");
					if (!f.syscall_map[i].used) {
//						int found = execute_single_block(&f, find_block_from_addr(root, f.syscall_map[i].blk_address), sys_res);
						execute_single_block(&f, find_block_from_addr(root, f.syscall_map[i].blk_address), sys_res);
//						printf("%s", found?BGRN "[*]" GRN " New syscall number!\n" CRESET:BRED "[*]" RED " no luck!!!\n" CRESET);
					}
				}

				buf=print_res(sys_res, "0x%08lx\t%d\n");
//				eprintf(BGRN "[*]" GRN " Results:\n" CRESET);
				eprintf("%s", buf);
				putchar(0); // from marcin
			}
			free(v.blocks);
			free(p.blocks);
			dispose_cfg(root);
			dispose_res(sys_res, buf);
		} else {
//			eprintf(BRED "[*]" RED " Analysis failed due to an error!\n" CRESET);
			free(v.blocks);
			free(p.blocks);
			dispose_cfg(root);
			dispose_res(sys_res, buf);
			return RZ_CMD_STATUS_ERROR;
			}
	}
//	eprintf("\n");
	free(f.text);
	return RZ_CMD_STATUS_OK;
}

static bool sysno_init(RzCore *core) {
//	eprintf("[*] Sysno initialization...\n");
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		return false;
	}

	RzCmdDesc *cd = rz_cmd_desc_argv_new(rcmd, root_cd, "sysno", do_sysno, &sysno_help);
	if (!cd) {
		rz_warn_if_reached();
		return false;
	}

	return true;
}

static bool sysno_fini(RzCore *core) {
//	eprintf("[*] Sysno deinitialization...\n");
	return true;
}


RzCorePlugin sysno_plugin_desc = {
	.name = "Syscall Unicorn",
	.desc = "It provides syscall numbers used in the current function",
	.license = "MIT",
	.author = AUTHOR,
	.version = "0.0.1",
	.init = sysno_init,
	.fini = sysno_fini
};

#ifndef RZ_PLUGIN_INCORE
RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &sysno_plugin_desc,
	.version = RZ_VERSION
};
#endif
