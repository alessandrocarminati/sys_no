LDFLAGS += -lcapstone -lunicorn -lpthread -lm
LDFLAGS += -lrt
all:
	clang $(LDFLAGS) sample.c -o sample
