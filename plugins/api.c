/*
 * QEMU Plugin API
 *
 * This provides the API that is available to the plugins to interact
 * with QEMU. We have to be careful not to expose internal details of
 * how QEMU works so we abstract out things like translation and
 * instructions to anonymous data types:
 *
 *  qemu_plugin_tb
 *  qemu_plugin_insn
 *
 * Which can then be passed back into the API to do additional things.
 * As such all the public functions in here are exported in
 * qemu-plugin.h.
 *
 * The general life-cycle of a plugin is:
 *
 *  - plugin is loaded, public qemu_plugin_install called
 *    - the install func registers callbacks for events
 *    - usually an atexit_cb is registered to dump info at the end
 *  - when a registered event occurs the plugin is called
 *     - some events pass additional info
 *     - during translation the plugin can decide to instrument any
 *       instruction
 *  - when QEMU exits all the registered atexit callbacks are called
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */


#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "cpu.h"
#include "sysemu/sysemu.h"
#include "tcg/tcg.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "plugin.h"
#ifndef CONFIG_USER_ONLY
#include "qemu/plugin-memory.h"
#include "hw/boards.h"
#endif
#include "trace/mem.h"

/* Uninstall and Reset handlers */
#ifdef CONFIG_TAINT_ANALYSIS
void plugin_mem_rw(CPUState* env, uint64_t addr, void *buf, int len, int is_write);
#endif

void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, false);
}

void qemu_plugin_reset(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
    plugin_reset_uninstall(id, cb, true);
}

/*
 * Plugin Register Functions
 *
 * This allows the plugin to register callbacks for various events
 * during the translation.
 */

void qemu_plugin_register_vcpu_init_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_INIT, cb);
}

void qemu_plugin_register_vcpu_exit_cb(qemu_plugin_id_t id,
                                       qemu_plugin_vcpu_simple_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_EXIT, cb);
}

void qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                          qemu_plugin_vcpu_udata_cb_t cb,
                                          enum qemu_plugin_cb_flags flags,
                                          void *udata)
{
    plugin_register_dyn_cb__udata(&tb->cbs[PLUGIN_CB_REGULAR],
                                  cb, flags, udata);
}

void qemu_plugin_register_vcpu_tb_exec_inline(struct qemu_plugin_tb *tb,
                                              enum qemu_plugin_op op,
                                              void *ptr, uint64_t imm)
{
    plugin_register_inline_op(&tb->cbs[PLUGIN_CB_INLINE], 0, op, ptr, imm);
}

void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *udata)
{
    plugin_register_dyn_cb__udata(&insn->cbs[PLUGIN_CB_INSN][PLUGIN_CB_REGULAR],
        cb, flags, udata);
}
#ifdef SINA_PLUGIN_AFTER
void qemu_plugin_register_vcpu_after_insn_exec_cb(struct qemu_plugin_insn *insn,
                                            qemu_plugin_vcpu_udata_cb_t cb,
                                            enum qemu_plugin_cb_flags flags,
                                            void *udata)
{
    plugin_register_dyn_cb__udata(&insn->cbs[PLUGIN_CB_AFTERI][PLUGIN_CB_REGULAR],
                                  cb, flags, udata);
}
#endif

#ifdef CONFIG_2nd_CCACHE
void switch_mode(EXECUTION_MODE to, bool immediateJMP, uint64_t eip){
    if (eip!=0 && last_switched_eip==eip && to==CHECK){
        return;
    }
    else{
        last_switched_eip = eip;
        second_ccache_flag = to;
    }
#ifdef TARGET_X86_64
    CPUX86State *env = &(X86_CPU(current_cpu)->env);
#ifdef CONFIG_DEBUG_CCACHE_SWITCH
    uintptr_t pc = GETPC();
    printf("GETPC=%lx, env->eip=0x%lx, guest_eip=0x%lx, last_switched_eip=0x%lx\n",pc,env->eip,eip,last_switched_eip);
#endif
    if (eip!=0){
//        cpu_restore_state(current_cpu,eip,true);
    env->eip = eip;
    }
#endif
    //EXCP12_TNT=39
    current_cpu->exception_index = 39; //sina: longjmp works neater in comparison to raise_exception because the latter passes the exception to guest.
#ifdef CONFIG_DEBUG_CCACHE_SWITCH
    printf("switching to mode=%d\n",to);
#endif
    if(immediateJMP){
        cpu_loop_exit(current_cpu); // does the siglongjmp within
    }
}
#endif

void qemu_plugin_register_vcpu_insn_exec_inline(struct qemu_plugin_insn *insn,
                                                enum qemu_plugin_op op,
                                                void *ptr, uint64_t imm)
{
    plugin_register_inline_op(&insn->cbs[PLUGIN_CB_INSN][PLUGIN_CB_INLINE],
                              0, op, ptr, imm);
}



void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                      qemu_plugin_vcpu_mem_cb_t cb,
                                      enum qemu_plugin_cb_flags flags,
                                      enum qemu_plugin_mem_rw rw,
                                      void *udata)
{
    plugin_register_vcpu_mem_cb(&insn->cbs[PLUGIN_CB_MEM][PLUGIN_CB_REGULAR],
                                cb, flags, rw, udata);
}

void qemu_plugin_register_vcpu_mem_inline(struct qemu_plugin_insn *insn,
                                          enum qemu_plugin_mem_rw rw,
                                          enum qemu_plugin_op op, void *ptr,
                                          uint64_t imm)
{
    plugin_register_inline_op(&insn->cbs[PLUGIN_CB_MEM][PLUGIN_CB_INLINE],
        rw, op, ptr, imm);
}

void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                           qemu_plugin_vcpu_tb_trans_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_TB_TRANS, cb);
}

void qemu_plugin_register_vcpu_syscall_cb(qemu_plugin_id_t id,
                                          qemu_plugin_vcpu_syscall_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL, cb);
}

void
qemu_plugin_register_vcpu_syscall_ret_cb(qemu_plugin_id_t id,
                                         qemu_plugin_vcpu_syscall_ret_cb_t cb)
{
    plugin_register_cb(id, QEMU_PLUGIN_EV_VCPU_SYSCALL_RET, cb);
}

/*
 * Plugin Queries
 *
 * These are queries that the plugin can make to gauge information
 * from our opaque data types. We do not want to leak internal details
 * here just information useful to the plugin.
 */

/*
 * Translation block information:
 *
 * A plugin can query the virtual address of the start of the block
 * and the number of instructions in it. It can also get access to
 * each translated instruction.
 */

size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
    return tb->n;
}

uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb)
{
    return tb->vaddr;
}

struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx)
{
    if (unlikely(idx >= tb->n)) {
        return NULL;
    }
    return g_ptr_array_index(tb->insns, idx);
}

/*
 * Instruction information
 *
 * These queries allow the plugin to retrieve information about each
 * instruction being translated.
 */

const void *qemu_plugin_insn_data(const struct qemu_plugin_insn *insn)
{
    return insn->data->data;
}

size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *insn)
{
    return insn->data->len;
}

uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn)
{
    return insn->vaddr;
}

void *qemu_plugin_insn_haddr(const struct qemu_plugin_insn *insn)
{
    return insn->haddr;
}

char *qemu_plugin_insn_disas(const struct qemu_plugin_insn *insn)
{
    CPUState *cpu = current_cpu;
    return plugin_disas(cpu, insn->vaddr, insn->data->len);
}

#ifdef CONFIG_TAINT_ANALYSIS

void plugin_mem_rw(CPUState* env, uint64_t addr, void *buf, int len, int is_write) {
    cpu_memory_rw_debug(env, addr, buf, len, is_write);
}


void *cap_plugin_insn_disas(const struct qemu_plugin_insn *insn)
{
    CPUState *cpu = current_cpu;
    void *structure_ptr;
//    char *temp = structured_plugin_disas(cpu, insn->vaddr, insn->data->len, &structure_ptr);
    structured_plugin_disas(cpu, insn->vaddr, insn->data->len, &structure_ptr);
    return structure_ptr;
}

void plugin_mem_read(uint64_t vaddr, int len, void *buf)
{
    CPUState *cpu = current_cpu;
    plugin_mem_rw(cpu,vaddr,buf,len,0);
}

void plugin_reg_read(uint32_t reg, int len, void *buf)
{
    uint32_t qreg = reg;
    uint8_t shift = 0;
    uint64_t value =0 ;
#ifdef TARGET_X86_64
    CPUX86State *cpu = &(X86_CPU(current_cpu)->env);
    if(qreg>22 && qreg<29){
        qreg -= 23;
        value = (uint64_t)cpu->segs[qreg].base;
    }

    else{ //high parts of the general registers see i386/translate and access to AH for an example
        if(qreg==100){ //not a good idea but right now it's hardcoded
            value = cpu_compute_eflags(cpu);
        }
        else{
            if (qreg>15 && qreg<20){
                qreg -=16;
                shift = 1;
            }
            value = (uint64_t)cpu->regs[qreg];
        }
    }
//    printf("value=%lx, reg=%d qreg=%d\n",value,reg,qreg);
#endif
    if (shift){
        value = value >> 8;
    }
    switch(len){
        case 1:
            *(uint8_t*)buf = value & 0xff;
            break;
        case 2:
            *(uint16_t*)buf = value & 0xffff;
            break;
        case 4:
            *(uint32_t*)buf = value & 0xffffffff;
            break;
        case 8:
            *(uint64_t*)buf = value;
            break;
        default:
            printf("size for reg_read is not supported=%d\n",len);
            assert(0);
    }
}
#endif
/*
 * The memory queries allow the plugin to query information about a
 * memory access.
 */

unsigned qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info)
{
    return info & TRACE_MEM_SZ_SHIFT_MASK;
}

bool qemu_plugin_mem_is_sign_extended(qemu_plugin_meminfo_t info)
{
    return !!(info & TRACE_MEM_SE);
}

bool qemu_plugin_mem_is_big_endian(qemu_plugin_meminfo_t info)
{
    return !!(info & TRACE_MEM_BE);
}

bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info)
{
    return !!(info & TRACE_MEM_ST);
}

/*
 * Virtual Memory queries
 */

#ifdef CONFIG_SOFTMMU
static __thread struct qemu_plugin_hwaddr hwaddr_info;

struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr)
{
    CPUState *cpu = current_cpu;
    unsigned int mmu_idx = info >> TRACE_MEM_MMU_SHIFT;
    hwaddr_info.is_store = info & TRACE_MEM_ST;

    if (!tlb_plugin_lookup(cpu, vaddr, mmu_idx,
                           info & TRACE_MEM_ST, &hwaddr_info)) {
        error_report("invalid use of qemu_plugin_get_hwaddr");
        return NULL;
    }

    return &hwaddr_info;
}
#else
struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr)
{
    return NULL;
}
#endif

bool qemu_plugin_hwaddr_is_io(struct qemu_plugin_hwaddr *hwaddr)
{
#ifdef CONFIG_SOFTMMU
    return hwaddr->is_io;
#else
    return false;
#endif
}

uint64_t qemu_plugin_hwaddr_device_offset(const struct qemu_plugin_hwaddr *haddr)
{
#ifdef CONFIG_SOFTMMU
    if (haddr) {
        if (!haddr->is_io) {
            ram_addr_t ram_addr = qemu_ram_addr_from_host((void *) haddr->v.ram.hostaddr);
            if (ram_addr == RAM_ADDR_INVALID) {
                error_report("Bad ram pointer %"PRIx64"", haddr->v.ram.hostaddr);
                abort();
            }
            return ram_addr;
        } else {
            return haddr->v.io.offset;
        }
    }
#endif
    return 0;
}

/*
 * Queries to the number and potential maximum number of vCPUs there
 * will be. This helps the plugin dimension per-vcpu arrays.
 */

#ifndef CONFIG_USER_ONLY
static MachineState * get_ms(void)
{
    return MACHINE(qdev_get_machine());
}
#endif

int qemu_plugin_n_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->smp.cpus;
#endif
}

int qemu_plugin_n_max_vcpus(void)
{
#ifdef CONFIG_USER_ONLY
    return -1;
#else
    return get_ms()->smp.max_cpus;
#endif
}

/*
 * Plugin output
 */
void qemu_plugin_outs(const char *string)
{
    qemu_log_mask(CPU_LOG_PLUGIN, "%s", string);
}
