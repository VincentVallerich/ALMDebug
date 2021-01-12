CC=gcc
CDFLAGS=
LDFLAGS=
EXEC=fibonacci

all: $(EXEC)
$(EXEC): main.o
	$(CC) -o $@ $^ $(LDFLAGS)
%.o: %.c 
	$(CC) -c -g -no-pie $(CFLAGS) -o $@ $< 
main.o:
clean: 
	rm -rf *.o 
cleanall: clean 
	rm -f $(EXEC)