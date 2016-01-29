SUBDIRS += $(PLATDIR)/simics

QEMU_OBJS = simics.o
QEMU = $(PLATDIR)/simics/built-in.o
$(QEMU): $(QEMU_OBJS:%=$(PLATDIR)/simics/%)
