CROSS_COMPILE?=
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

CFLAGS=-W -Wall -I../include
LDFLAGS=-lapu -L.
EXEC=libapu_test
OBJ=apu.o memory.o ion.o
HDR=../include/rich-iot/apu.h ../include/rich-iot/apu-host.h ../include/rich-iot/memory.h ion.h

all: libapu_test

libapu.a: $(OBJ) $(HDR)
	@$(AR) rc libapu.a $(OBJ)

libapu: libapu.a

libapu_test: libapu test.o
	@$(CC) -o $@ test.o $(CFLAGS) $(LDFLAGS)

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf *.o

mrproper: clean
	@rm -rf libapu_test libapu.a
