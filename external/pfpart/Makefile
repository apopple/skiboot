CFLAGS = -O2 -I. -Wall -g3
#LDFLAGS =
CC     = $(CROSS_COMPILE)gcc

SRCS   := libflash/libflash.c libflash/libffs.c pfpart.c
OBJS   := $(SRCS:.c=.o)
EXE    := pfpart

all: $(EXE)

PHONY: links
links:
	ln -fs ../../libflash
	ln -fs ../../ccan

$(OBJS) : links

$(EXE): $(OBJS)
	$(LINK.c) $^ -o $@

.PHONY: clean
clean:
	$(RM) $(OBJS) $(EXE)

.PHONY: distclean
distclean:
	$(RM) *.c~ *.h~ *.i *.s Makefile~ libflash/*.c~ libflash/*.h~
	$(RM) libflash ccan
