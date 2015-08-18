# -*-Makefile-*-

SUBDIRS += librust

# Core Rust libraries that we need
librust/librustc_unicode.rlib: librust/libcore.rlib
librust/liballoc.rlib: librust/libcore.rlib
librust/libcollections.rlib: librust/librustc_unicode.rlib librust/liballoc.rlib

# Minimum set of standard libraries
librust/libstd.rlib: librust/libcollections.rlib
librust/liblibc.rlib: librust/libstd.rlib
librust/liballoc_system.rlib: librust/liblibc.rlib

LIBRUST_OBJS  = liballoc_system.rlib liblibc.rlib libstd.rlib
LIBRUST = $(LIBRUST_OBJS:%=librust/%)
