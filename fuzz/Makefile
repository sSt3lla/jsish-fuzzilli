JSIROOT=..
ACFLAGS= -g -Wall -I$(JSIROOT) -I$(JSIROOT)/src
CFLAGS=$(ACFLAGS)
LIBJSI=libjsish.a
JSISH=$(JSIROOT)/jsish
ALDFLAGS=-lm -ldl -lpthread
-include $(JSIROOT)/make.conf

XCFLAGS += -fsanitize=address -fno-omit-frame-pointer -fsanitize-coverage=trace-pc-guard -O2
LDFLAGS += -fsanitize=address -fsanitize-coverage=trace-pc-guard

#XCFLAGS += -ggdb3 -O0
#LDFLAGS += 


LDFLAGS += $(LIBJSI) $(ALDFLAGS)
SHFLAGS=-shared -fpic 
ALLDEPS=$(JSIROOT)/jsish.c $(JSIROOT)/libjsish.so $(JSIROOT)/src/jsi.h Makefile

SLDFLAGS=-Wl,-rpath=`pwd`/$(JSIROOT) -L$(JSIROOT) -ljsish $(ALDFLAGS)
CC=clang

all: fuzz

libjsi.a: $(JSIROOT)/jsi.c
	$(CC) $(CFLAGS) $< -c -o jsi.o
	$(AR) rv libjsi.a jsi.o

libjsish.a: $(JSIROOT)/jsish.c
	$(CC) $(CFLAGS) $< -I.. -c -o jsish.o
	$(AR) rv libjsish.a jsish.o

libjsish.so: $(JSIROOT)/jsish.c
	$(CC) $(ACFLAGS) $(SHFLAGS) $< -rdynamic -o $@

jsishs: $(JSIROOT)/jsish.c
	$(CC) $(ACFLAGS) -fpic -DJSI__MAIN=1 $< -rdynamic -o $@ -lm -ldl -lpthread
	jsish -z create $@ $(JSIROOT)/lib

fuzz: fuzz.c $(ALLDEPS)
	$(CC) $(CFLAGS) $(XCFLAGS) -o $@ $< $(SLDFLAGS)


clean:
	rm -rf fuzz

.PHONY: all clean
