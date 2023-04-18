#ifndef R2PI_SYSNO_H

#define R2PI_SYSNO_H

#define PLUGIN_NAME "sysno"

#define PROC_CMD_PARSE(cmd, args) 			\
({							\
	int i=0,argc=0;					\
	char *cmdw=(char *)cmd;				\
	args[argc++]=(char *)cmd;			\
	while (*(cmdw+i)) {				\
		if (*(cmdw+i)==0x20) {			\
			args[argc++]=(char *)(cmdw+i);	\
			*(cmdw+i)=0;			\
			}				\
		if (argc>9) break;			\
		i++;					\
		}					\
	argc;						\
})

#endif
