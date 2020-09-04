CROSS_COMPILE?=
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

CFLAGS=-W -Wall -I../include -I../include/xrp
LDFLAGS=-lapu -L. -lpthread
EXEC=libapu_test
OBJ=apu.o memory.o ion.o
HDR=../include/rich-iot/apu.h ../include/rich-iot/apu-host.h ../include/rich-iot/memory.h ion.h

XRPOBJ=xrp/xrp.o
XRPHDR= $(HDR) ../include/xrp/xrp_api.h

all: libapu_test

libapu.a: $(OBJ) $(HDR)
	@$(AR) rc libapu.a $(OBJ)

libapu: libapu.a

libapu_test: libapu test.o
	@$(CC) -o $@ test.o $(CFLAGS) $(LDFLAGS)

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAGS)

libxrp.a: $(XRPOBJ) $(XRPHDR)
	@$(AR) rc libxrp.a $(XRPOBJ)

libxrp: libxrp.a

xrp_test: libapu libxrp xrp/host_main.o
	@$(CC) -o $@ xrp/host_main.o $(CFLAGS) $(LDFLAGS) -lxrp -lapu

xrp/%.o: xrp/%.c
	@$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf *.o xrp/*.o

mrproper: clean
	@rm -rf libapu_test libapu.a xrp_test libxrp.a
