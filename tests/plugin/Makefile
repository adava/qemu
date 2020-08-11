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
#QEMU_LDFLAGS += -lstdc++

all: $(SONAMES)

libSE_labels.so: SE_labels.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS) $(SRC_PATH)/tests/plugin/lib/SE/dfsan.o  $(SRC_PATH)/tests/plugin/lib/SE/union_util.o $(SRC_PATH)/tests/plugin/lib/SE/union_hashtable.o $(SRC_PATH)/tests/plugin/lib/SE/taint_allocator.o

lib%.so: %.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
