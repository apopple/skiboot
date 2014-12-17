CFLAGS = -O2 -I. -Wall -g3
#LDFLAGS =
CC     = $(CROSS_COMPILE)gcc

SRCS   		:= libflash/libflash.c libflash/libffs.c pfpart.c
OBJS   		:= $(SRCS:.c=.o)
EXE		:= pfpart
ECC_SRCS	:= ecc.c clib-ecc.c
ECC_EXE		:= ecc
ECC_OBJS   	:= $(ECC_SRCS:.c=.o)

all: $(EXE) $(ECC_EXE)

PHONY: links
links:
	ln -fs ../../libflash
	ln -fs ../../ccan

$(OBJS) : links

$(EXE): $(OBJS)
	$(LINK.c) $^ -o $@
	ln -fs pfpart fcp

$(ECC_EXE): CFLAGS += --std=gnu99
$(ECC_EXE): $(ECC_OBJS)
	$(LINK.c) $^ -o $@

.PHONY: clean
clean:
	$(RM) $(OBJS) $(EXE) $(ECC_OBJS) $(ECC_EXE)

.PHONY: distclean
distclean:
	$(RM) *.c~ *.h~ *.i *.s Makefile~ libflash/*.c~ libflash/*.h~
	$(RM) libflash ccan fcp
