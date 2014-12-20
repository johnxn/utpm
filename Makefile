IDIR = ./include
CFLAGS = -I$(IDIR) -fpic -shared
OBJ = hmac.o sha1.o stuff_inoutbuf.o utpm_functions.o utils.o tpm_marshalling.o

libutpm.a: $(OBJ)
	ar -r $@ $^ 

%.o: %.c 
	gcc -c -o $@ $< $(CFLAGS) 

clean:
	-rm *.a *.o
