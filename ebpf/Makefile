CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

all: stob_kern.o

stob_kern.o: stob_kern.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f stob_kern.o
