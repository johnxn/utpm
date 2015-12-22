all: test init_keys

test:
	gcc test_lib.c -lutpm -L . -I ./include/ -o test

init_keys:
	gcc init_keys.c -lutpm -L . -I ./include/ -o init_keys

clean: 
	rm -rf test init_keys

.PHONY: all clean

