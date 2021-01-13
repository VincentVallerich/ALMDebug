CC=gcc
CP=g++
CDFLAGS=
LDFLAGS=
EXEC=fibonacci
DBG=dbg

all: $(EXEC) $(DBG)
$(EXEC): fibonacci.o
	$(CC) -o $@ $^ $(LDFLAGS)
$(DBG): dbg.o
	$(CP) -o $@ $^ $(LDFLAGS)
fibonacci.o: fibonacci.c 
	$(CC) -c -g -no-pie $(CFLAGS) -o $@ $< 
dbg.o: main.cpp
	$(CP) -c -g -no-pie $(CFLAGS) -o $@ $< 
clean: 
	rm -rf *.o 
cleanall: clean 
	rm -f $(EXEC)