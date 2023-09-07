#include <r_core.h>
#include <r_anal.h>
#include <string.h>
#include "../include/cfg.h"
#include "../include/paths.h"
#include "../include/exec.h"
#include "../include/global_defines.h"
#include "../include/ansi_term.h"
#include "r2pi_sysno.h"


int execute_block_seq(struct exec_item *f, struct block_list *b, struct sys_results *sys_res){
	uc_engine *uc;
	int i, err;

	err=emu_init(f->text, f->base_address, f->length, &uc);
	if (err) return 1;

	for (i=0; i<b->blocks_no; i++) {
		DBG_PRINT(">>>>>>>>>>>>>>>>>>> Execution #%02d start <<<<<<<<<<<<<<<<<<<\n",i);
		DBG_PRINT("Execute block #%d, start=0x%08x, end=0x%08x\n",i, b->blocks_addr[i]->start, b->blocks_addr[i]->end);
		err=execute_block(uc, b->blocks_addr[i], sys_res);
		DBG_PRINT("Execution error flag=%d\n",err);
		if ((err!=SUCCESS)&&(err!=SYSCALL)) return 1;
#ifdef DEBUG
		dump_registers(uc);
#endif
		DBG_PRINT(">>>>>>>>>>>>>>>>>>> Execution #%02d end <<<<<<<<<<<<<<<<<<<\n",i);
		}
	emu_stop(uc);
	return 0;
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
		RCore *core = (RCore *) user;
		RAnalFunction *func = r_anal_get_fcn_in(core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
		if (!func) {
			eprintf (BRED "[*]" RED "no anal data, please run analysis before calling this\n" CRESET);
			return true;
			}
		ut64 fcnlsize = r_anal_function_linear_size(func);
//		ut64 fcnrsize = r_anal_function_realsize(func);
//		eprintf ("%s: [0x%08lx] lsize=%ld rsize=%ld name=%s %s argc=%d\n", PLUGIN_NAME, core->offset, fcnlsize, fcnrsize, func->name, cmd, n);
		struct exec_item f = {};
		f.base_address=core->offset;
		f.length=fcnlsize;
		f.text=malloc(f.length);
		if (r_io_read_at (core->io, f.base_address, f.text, f.length) ) {
//			for (uint32_t i=0; i<f.length; i++) eprintf("%02x ", *(f.text+i));
			struct block_list v={.blocks=NULL, .blocks_no=0}, p={.blocks=NULL, .blocks_no=0};
			struct Block *root;
			int tmp=0;
			struct sys_results *sys_res;
			char *buf = NULL;

			v.blocks=(uint64_t *) malloc(MAX_BLOCKS*sizeof(uint64_t));
			p.blocks_addr=(struct Block **) malloc(MAX_BLOCKS*sizeof(uint64_t));
			sys_res=init_res();
			patch_calls(&f);
			root=build_cfg(&f);
			if (root == NULL) {
				eprintf(BRED "[*]" RED " Function disassembly failed!!!\n" CRESET);
			}
			else {
				eprintf(BGRN "[*]" GRN " Generating cfg for the given function\n" CRESET);
				while (search_next(root, HOST_ADDRESS, &v, &p, 0, &tmp)!=NO_FOUND) {
					if (execute_block_seq(&f, &p, sys_res)) {
						eprintf(BRED "[*]" RED " Premature termination!!!\n" CRESET);
						break;
					}
				}
				buf=print_res(sys_res, "{address: \"0x%08lx\", number:\"%d\"}");
				eprintf(BGRN "[*]" GRN " Results:\n" CRESET);
				eprintf("%s\n", buf);
			}
			dispose_res(sys_res, buf);
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
