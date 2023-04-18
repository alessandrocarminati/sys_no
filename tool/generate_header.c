#include <stdio.h>
#include <stdlib.h>


#define HEADER "#ifndef GLOBAL_DEFINES_H\n#define GLOBAL_DEFINES_H\n"
#define FOOTER "#endif\n"
const char	*conf_env[]={"C_DEBUG","C_DEMO"};
const char	*conf_itm[]={"#define DEBUG","#define DEMO"};


int main(){
	printf(HEADER);
	for (int i=0; i<sizeof(conf_env)/sizeof(conf_env[0]); i++) {
		if(getenv(conf_env[i])){
			printf("%s\n",conf_itm[i]);
			}
		}
	printf(FOOTER);
}
