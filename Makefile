LDFLAGS += -lcapstone -lunicorn -lpthread -lm
LDFLAGS += -lrt
CC=clang
main:
	$(CC) main.c cfg.c paths.c exec.c -lunicorn -lcapstone -o main
clean:
	rm main
