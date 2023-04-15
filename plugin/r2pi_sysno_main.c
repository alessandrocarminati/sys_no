#include <r_core.h>
#include <string.h>
#include "r2pi_sysno.h"


static int do_sysno(void* user, const char* cmd) {
	int n;
	char *args[7];

	if (strncmp("sysno", cmd, 5)==0) {
		n=PROC_CMD_PARSE(cmd, args);
		if ((n<2)|| (n>3)) {
			eprintf ("Dummy! syntax error!\n");
			return true;
			}
		RCore *core = (RCore *) user;
		eprintf ("Dummy! [0x%08lx] %s argc=%d\n", core->offset, cmd, n);
		return true;
		}
	return false;
}

// Define your plugin's name and description
RCorePlugin core_plugin_desc = {
	.name = "Syscall Unicorn",
	.desc = "It provides syscall numbers used in a given function",
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
