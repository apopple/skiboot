
CFLAGS = -O2 -I. -Wall -DHAVE_LITTLE_ENDIAN
LDFLAGS = -lrt
CC     = $(CROSS_COMPILE)gcc

SRCS   := libflash/libflash.c libflash/libffs.c memboot.c progress.c \
	ast-sf-ctrl.c arm_io.c
OBJS   := $(SRCS:.c=.o)
EXE    := memboot

all: $(EXE)

PHONY: links
links:
	ln -fs ../../libflash
	ln -fs ../../ccan
	ln -fs ../../hw/sfc-ctrl.c
	ln -fs ../../hw/ast-bmc/ast-sf-ctrl.c
	ln -fs ../pflash/progress.c
	ln -fs ../pflash/progress.h
	ln -fs ../pflash/config.h
	ln -fs ../pflash/ast.h
	ln -fs ../pflash/io.h
	ln -fs ../pflash/arm_io.c

$(OBJS) : links

$(EXE): $(OBJS)
        $(LINK.c) $^ -o $@

.PHONY: clean
clean:
	$(RM) $(OBJS) $(EXE)

.PHONY: distclean
distclean:
	$(RM) *.c~ *.h~ *.i *.s Makefile~ libflash/*.c~ libflash/*.h~
	$(RM) libflash ccan sfc-ctrl.c ast-sf-ctrl.c
