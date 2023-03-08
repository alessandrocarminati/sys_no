LDFLAGS += -lcapstone -lunicorn -lpthread -lm
LDFLAGS += -lrt
sample:
	clang $(LDFLAGS) sample.c -o sample
main:
	clang main.c cfg.c paths.c exec.c -lunicorn -lcapstone -o main
test1:
	clang test1.c -o test1
clean:
	rm sample cfg2 test1
