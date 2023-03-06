LDFLAGS += -lcapstone -lunicorn -lpthread -lm
LDFLAGS += -lrt
sample:
	clang $(LDFLAGS) sample.c -o sample
cfg2:
	clang cfg2.c cfg.c paths.c -lcapstone -o cfg2
test1:
	clang test1.c -o test1
clean:
	rm sample cfg2 test1
