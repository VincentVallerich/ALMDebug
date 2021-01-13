CC=gcc
CP=g++
CDFLAGS=
LDFLAGS=-lopcodes -lbfd
EXEC=fibonacci
DBG=dbg

all: $(EXEC) $(DBG) clean
$(EXEC): fibonacci.o
	$(CC) -o $@ $^ $(LDFLAGS)
$(DBG): dbg.o symbol.o
	$(CP) -o $@ $^ $(LDFLAGS)
fibonacci.o: fibonacci.c 
	$(CC) -c -g -no-pie $(CFLAGS) -o $@ $<
symbol.o: symbol.cpp symbol.h
	$(CP) -c -g -no-pie $(CFLAGS) -o $@ $<
dbg.o: main.cpp symbol.h
	$(CP) -c -g -no-pie $(CFLAGS) -o $@ $< 
clean: 
	rm -rf *.o 
cleanall: clean 
	rm -f $(EXEC) $(DBG)