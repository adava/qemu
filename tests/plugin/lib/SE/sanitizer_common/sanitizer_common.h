//===-- sanitizer_common.h --------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is shared between run-time libraries of sanitizers.
//
// It declares common functions and classes that are used in both runtimes.
// Implementation of some functions are provided in sanitizer_common, while
// others must be defined by run-time library itself.
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_COMMON_H
#define SANITIZER_COMMON_H

#include <errno.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
using namespace __dfsan;

namespace __sanitizer {

    void internal_iserror(int retval, char *err) {
        if (retval < 0) {
            if (errno)
                perror(err);
        }
        assert(retval>=0);
    }

    void UnmapOrDie(void *addr, uint64_t size) {
        if (!addr || !size) return;
        uint64_t res = munmap(addr, size);
        if (res == -1) {
            printf("ERROR: failed to deallocate 0x%zx (%zd) bytes at address %p\n", size, size, addr);
            assert(0);
        }
    }

    int GetNamedMappingFd(const char *name, uint32_t size, int *flags) {
        if (!name)
            return -1;
        char shmname[200];
        snprintf(shmname, sizeof(shmname), "/dev/shm/%d [%s]", getpid(), name);
        int fd = open(shmname, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRWXU);
        assert(fd >= 0);
        int res = ftruncate(fd, size);
//    printf("%s res=%d\n",shmname,res);
        internal_iserror(res, (char *) "ftruncate error");
        res = unlink(shmname);
        assert(res == 0);
        return fd;
    }

    void *MmapNamed(void *addr, uint64_t length, int prot, int flags) {
//    printf("mapping addr=0x%p, size=0x%lx\n",addr, length);
//    int fd = GetNamedMappingFd(name, length, &flags);
//    void *res = mmap(addr, length, prot, flags, fd, 0);
        void *res = mmap(NULL, length, prot, flags, -1, 0);

        if (res > 0) {
//        prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, (uint64_t)name);
//        printf("mmap res=%p\n",res);
            return res;
        } else {
            printf("ERROR: failed to allocate 0x%zx (%zd) bytes at address %p \n", length, length, addr);
            assert(0);
        }
    }

    static bool MmapFixed(uint64_t fixed_addr, uint64_t size, int additional_flags, void **shadow_start) {
        size = (size + 4096 - 1) & ~(4096 - 1);
        fixed_addr = fixed_addr & ~(4096 - 1);
        *shadow_start =  MmapNamed((void *) fixed_addr, size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE /*| MAP_FIXED */ | additional_flags | MAP_ANON); //sina: MAP_FIXED fails when not position dependent
        return true;
    }

    bool MmapFixedNoReserve(uint64_t fixed_addr, uint64_t size, void **shadow_start) {
        return MmapFixed(fixed_addr, size, MAP_NORESERVE, shadow_start);
    }

    void *MmapFixedNoAccess(uint64_t fixed_addr, uint64_t size) {
        return (void *) MmapNamed((void *) fixed_addr, size, PROT_NONE,
                                  MAP_PRIVATE /*| MAP_FIXED */ | MAP_NORESERVE | MAP_ANON);
    }

    void Die(char *msg)
    {
        printf("%s",msg);
        exit(1);
    }
    void Die()
    {
        exit(1);
    }
    // Don't use std::min, std::max or std::swap, to minimize dependency
// on libstdc++.
    template<class T> T Min(T a, T b) { return a < b ? a : b; }
    template<class T> T Max(T a, T b) { return a > b ? a : b; }
    template<class T> void Swap(T& a, T& b) {
        T tmp = a;
        a = b;
        b = tmp;
    }

}

#endif  // SANITIZER_COMMON_H
