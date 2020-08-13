BUILD_DIR := $(CURDIR)/../..

include $(BUILD_DIR)/config-host.mak
include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/tests/plugin)

#this path must contain the following: dfsan.cc, taint_allocator.cc, union_util.cc, union_hashtable.cc
SE_LIB_DIR :=   $(SRC_PATH)/tests/plugin/lib/SE
CXX := g++

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

DFSLAN_LIB := $(SE_LIB_DIR)/dfsan
UNION_LIB := $(SE_LIB_DIR)/union_util
HASHTABLE_LIB += $(SE_LIB_DIR)/union_hashtable
TAINTALLOC_LIB += $(SE_LIB_DIR)/taint_allocator

SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

QEMU_CFLAGS += -fPIC -Wno-unused-but-set-variable -Wno-unused-function
QEMU_CFLAGS += -I$(SRC_PATH)/include/qemu
#QEMU_LDFLAGS += -lstdc++
SE_LIB_CFLAGS += -fPIC -Wno-unused-but-set-variable -Wno-unused-function

all: $(SONAMES)

libSE_labels.so: SE_labels.o $(DFSLAN_LIB).o $(UNION_LIB).o $(HASHTABLE_LIB).o $(TAINTALLOC_LIB).o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^

$(SE_LIB_DIR)/%.o: $(SE_LIB_DIR)/%.cc
	$(CXX) $(SE_LIB_CFLAGS) -shared -std=gnu++11 -o $@ $^ `pkg-config --cflags glib-2.0` `pkg-config --libs glib-2.0`

lib%.so: %.o
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs
	rm $(SE_LIB_DIR)/*.o

.PHONY: all clean
