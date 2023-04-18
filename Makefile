CC=clang

EXTRA_CFLAGS= -Wno-error=unused-parameter -Wno-error=unused-function
CFLAGS = -Wall -Wextra -Werror -O2 -fPIC $(EXTRA_CFLAGS)
LDFLAGS = -shared -lr_core

AUTHOR = $(shell git config user.name)

PLUGIN_NAME = sysno
RADARE_LOCAL_PLUGIN = ~/.local/share/radare2/plugins
PLUGIN_SRC = plugin/r2pi_sysno_main.c
RADARE2_DIR = ../radare2
BUILD_DIR = build

#DEBUG=_debug

all:
	@echo no action use "plugin or demo".

plugin: plugin_h$(DEBUG) $(BUILD_DIR)/$(PLUGIN_NAME).so
	echo plugin is available at $(BUILD_DIR)/$(PLUGIN_NAME).so

demo: demo_h$(DEBUG) $(BUILD_DIR)/demo
	echo Demo app is at $(BUILD_DIR)/demo

demo_h: export C_DEMO=yes
demo_h: $(BUILD_DIR)/generate_header
	$(BUILD_DIR)/generate_header >include/global_defines.h

demo_h_debug: export C_DEBUG=yes
demo_h_debug: export C_DEMO=yes
demo_h_debug: $(BUILD_DIR)/generate_header
	$(BUILD_DIR)/generate_header >include/global_defines.h

plugin_h_debug: export C_DEBUG=yes
plugin_h_debug: $(BUILD_DIR)/generate_header
	$(BUILD_DIR)/generate_header >include/global_defines.h

plugin_h: $(BUILD_DIR)/generate_header
	$(BUILD_DIR)/generate_header >include/global_defines.h

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(PLUGIN_NAME).so: $(PLUGIN_SRC) $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -I$(RADARE2_DIR)/libr/include -I$(RADARE2_DIR)/shlr/sdb/src -L$(RADARE2_DIR)/libr/core/ $(PLUGIN_SRC) $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o -DAUTHOR="\"$(AUTHOR)\"" -lunicorn -lcapstone

$(BUILD_DIR)/demo: $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o demo/fp.c demo/main.c $(BUILD_DIR)/generate_header
	$(CC) $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o demo/fp.c demo/main.c -lunicorn -lcapstone -g -o $(BUILD_DIR)/demo

$(BUILD_DIR)/generate_header: $(BUILD_DIR) tool/generate_header.c
	$(CC) -o $@ tool/generate_header.c

objects: build build/cfg.o build/paths.o build/exec.o build/helper.o
	echo

$(BUILD_DIR)/cfg.o: $(BUILD_DIR) src/cfg.c include/global_defines.h
	$(CC) src/cfg.c -c -o $@

$(BUILD_DIR)/paths.o: $(BUILD_DIR) src/paths.c
	$(CC) src/paths.c -c -o $@

$(BUILD_DIR)/exec.o: $(BUILD_DIR) src/exec.c
	$(CC) src/exec.c -c -o $@

$(BUILD_DIR)/helper.o: $(BUILD_DIR) src/helper.c
	$(CC) src/helper.c -c -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm include/global_defines.h

install: plugin
	cp $(BUILD_DIR)/$(PLUGIN_NAME).so $(RADARE_LOCAL_PLUGIN)
	echo Radare Plugin installed at $(RADARE_LOCAL_PLUGIN)
