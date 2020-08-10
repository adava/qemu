BUILD_DIR := $(CURDIR)/../..

include $(BUILD_DIR)/config-host.mak
include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/tests/plugin)

#the following must be compiled first: dfsan.cc, taint_allocator.cc, union_util.cc, union_hashtable.cc

NAMES :=
NAMES += bb
NAMES += empty
NAMES += insn
NAMES += mem
NAMES += hotblocks
NAMES += howvec
NAMES += hotpages
NAMES += taint
NAMES += labels
NAMES += SE_labels

SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

QEMU_CFLAGS += -fPIC -Wno-unused-but-set-variable -Wno-unused-function
QEMU_CFLAGS += -I$(SRC_PATH)/include/qemu

all: $(SONAMES)

libSE_labels.so: SE_labels.o
	$(CC) ./lib/SE/dfsan.o ./lib/SE/taint_allocator.o ./lib/SE/union_util.o ./lib/SE/union_hashtable.o -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

lib%.so: %.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
