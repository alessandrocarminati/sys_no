CC=clang

EXTRA_CFLAGS= -Wno-error=unused-parameter -Wno-error=unused-function -Wno-error=unused-command-line-argument -Wno-error=sign-compare
PKG_CONFIG_FLAGS = `pkg-config --cflags --libs rz_core`
CFLAGS = -Wall -Wextra -Werror -O2 -fPIC $(PKG_CONFIG_FLAGS) $(EXTRA_CFLAGS)
LDFLAGS = -shared -lcapstone -lunicorn

AUTHOR = $(shell git config user.name)

PLUGIN_NAME = sysno
RIZIN_LOCAL_PLUGIN = ~/.local/lib64/rizin/plugins
PLUGIN_SRC = plugin/r2pi_sysno_main.c
BUILD_DIR = build

DEBUG=_debug

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
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PLUGIN_SRC) $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o -DAUTHOR="\"$(AUTHOR)\""

$(BUILD_DIR)/demo: $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o demo/fp.c demo/main.c $(BUILD_DIR)/generate_header
	$(CC) $(BUILD_DIR)/cfg.o $(BUILD_DIR)/paths.o $(BUILD_DIR)/exec.o $(BUILD_DIR)/helper.o demo/fp.c demo/main.c -g -o $(BUILD_DIR)/demo

$(BUILD_DIR)/generate_header: $(BUILD_DIR) tool/generate_header.c
	$(CC) -o $@ tool/generate_header.c

objects: build build/cfg.o build/paths.o build/exec.o build/helper.o
	echo

$(BUILD_DIR)/cfg.o: $(BUILD_DIR) src/cfg.c include/global_defines.h
	$(CC) $(CFLAGS) src/cfg.c -c -o $@

$(BUILD_DIR)/paths.o: $(BUILD_DIR) src/paths.c
	$(CC) $(CFLAGS) src/paths.c -c -o $@

$(BUILD_DIR)/exec.o: $(BUILD_DIR) src/exec.c
	$(CC) $(CFLAGS) src/exec.c -c -o $@

$(BUILD_DIR)/helper.o: $(BUILD_DIR) src/helper.c
	$(CC) src/helper.c -c -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm include/global_defines.h

install: plugin
	mkdir -p $(RIZIN_LOCAL_PLUGIN)
	cp $(BUILD_DIR)/$(PLUGIN_NAME).so $(RIZIN_LOCAL_PLUGIN)
	echo Rizin Plugin installed at $(RIZIN_LOCAL_PLUGIN)
