CFLAGS = -I ../include -I .
CLIBS = -lRockeyARM -lpthread

OBJ = rockey_apis.o tpm_marshalling.o stuff_inoutbuf.o utils.o management.o utils.o hmac.o sha1.o

init_rockey: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(CLIBS)

rockey_apis.o: ../rockey_apis.c
	gcc -c -o $@ $< $(CFLAGS)

stuff_inoutbuf.o: ../stuff_inoutbuf.c
	gcc -c -o $@ $< $(CFLAGS)

tpm_marshalling.o: ../tpm_marshalling.c
	gcc -c -o $@ $< $(CFLAGS)

utils.o: ../utils.c
	gcc -c -o $@ $< $(CFLAGS)

hmac.o: ../hmac.c
	gcc -c -o $@ $< $(CFLAGS)

sha1.o: ../sha1.c
	gcc -c -o $@ $< $(CFLAGS)

management.o: management.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	-rm *.o init_rockey

