CFLAGS = -I ../include -I . 
CLIBS = -lRockeyARM -lpthread
OBJ = rockey_apis.o command_handler.o utpmd.o


utpmd: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(CLIBS)

rockey_apis.o: ../rockey_apis.c
	gcc -c -o $@ $< $(CFLAGS)

command_handler.o: command_handler.c
	gcc -c -o $@ $< $(CFLAGS)

utpmd.o: utpmd.c
	gcc -c -o $@ $< $(CFLAGS)

clean:
	-rm *.o utpmd
