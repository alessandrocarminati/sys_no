CC=clang

EXTRA_CFLAGS= -Wno-error=unused-parameter
CFLAGS = -Wall -Wextra -Werror -O2 -fPIC $(EXTRA_CFLAGS)
LDFLAGS = -shared -lr_core

PLUGIN_NAME = sysno
PLUGIN_SRC = sysno_main.c

RADARE2_DIR = ../radare2

all: $(PLUGIN_NAME).so

$(PLUGIN_NAME).so: $(PLUGIN_SRC)
        $(CC) $(CFLAGS) $(LDFLAGS) -o $@ -I$(RADARE2_DIR)/libr/include -I$(RADARE2_DIR)/shlr/sdb/src -L$(RADARE2_DIR)/libr/core/ $<

main: cfg.c paths.c exec.c helper.c fp.c main.c
	$(CC) main.c cfg.c paths.c exec.c helper.c fp.c -lunicorn -lcapstone -g -o main
clean:
	rm main
objects: cfg.o paths.o exec.o helper.o
	echo

cfg.o: cfg.c
	$(CC) $< -c -o $@

paths.o: paths.c
	$(CC) $< -c -o $@

exec.o: exec.c
	$(CC) $< -c -o $@

helper.o: helper.c
	$(CC) $< -c -o $@

clean:
        rm -f $(PLUGIN_NAME).so

