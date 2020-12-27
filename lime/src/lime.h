/*
 * LiME - Linux Memory Extractor
 * Copyright (c) 2011-2014 Joe Sylve - 504ENSICS Labs
 *
 *
 * Author:
 * Joe Sylve       - joe.sylve@gmail.com, @jtsylve
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __LIME_H_
#define __LIME_H_

#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#include <net/sock.h>
#include <net/tcp.h>

#include <linux/io.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
#include <crypto/hash.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 11)
#include <linux/crypto.h>
#endif

#define LIME_RAMSTR "System RAM"
#define LIME_MAX_FILENAME_SIZE 256
#define LIME_MAGIC 0x4C694D45 //LiME

#define LIME_MODE_RAW 0
#define LIME_MODE_LIME 1
#define LIME_MODE_PADDED 2

#define LIME_METHOD_UNKNOWN 0
#define LIME_METHOD_TCP 1
#define LIME_METHOD_DISK 2

#define LIME_DIGEST_FAILED -1
#define LIME_DIGEST_COMPLETE 0
#define LIME_DIGEST_COMPUTE 1

#ifdef LIME_DEBUG
#define DBG(fmt, args...) do { printk("[LiME] "fmt"\n", ## args); } while (0)
#else
#define DBG(fmt, args...) do {} while(0)
#endif

#define RETRY_IF_INTERRUPTED(f) ({ \
    ssize_t err; \
    do { err = f; } while(err == -EAGAIN || err == -EINTR); \
    err; \
})

// Disable timing... too strict!
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
// #define LIME_SUPPORTS_TIMING
// #endif

#ifdef CONFIG_ZLIB_DEFLATE
#define LIME_SUPPORTS_DEFLATE
#endif

//structures

typedef struct {
    unsigned int magic;
    unsigned int version;
    unsigned long long s_addr;
    unsigned long long e_addr;
    unsigned char reserved[8];
} __attribute__ ((__packed__)) lime_mem_range_header;

//SGX defs
#ifndef MSR_IA32_FEAT_CTL
#define MSR_IA32_FEAT_CTL                   MSR_IA32_FEATURE_CONTROL
#endif
#ifndef FEAT_CTL_LOCKED
#define FEAT_CTL_LOCKED FEATURE_CONTROL_LOCKED
#endif
#define FEAT_CTL_SGX_ENABLED                (1<<18)
#define X86_FEATURE_SGX		            (9 * 32 + 2)
#define SGX_MAX_EPC_BANKS                   128
#define SGX_CPUID		            0x12
#define SGX_CPUID_FIRST_VARIABLE_SUB_LEAF   2
#define SGX_CPUID_SUB_LEAF_TYPE_MASK	    GENMASK(3, 0)
#define SGX_CPUID_SUB_LEAF_INVALID          0x0
#define SGX_CPUID_SUB_LEAF_EPC_SECTION      0x1
#define EDGBRD                              0x04
#define ENCLS_FAULT_FLAG                    0x40000000

// MACROs from INTEL SGX SDK
#define enclave_op(rax, data, rcx)                     \
        ({                                              \
        unsigned long rbx_out;                          \
        int ret = __encls_N(rax, rbx_out, "c"(rcx));    \
        if (!ret)                                       \
                *data = rbx_out;                         \
        ret;                                            \
        })

#define __encls_N(rax, rbx_out, inputs...)                      \
        ({                                                      \
        int ret;                                                \
        asm volatile(                                           \
        "1: .byte 0x0f, 0x01, 0xcf;\n\t"                        \
        "   xor %%eax,%%eax;\n"                                 \
        "2:\n"                                                  \
        ".section .fixup,\"ax\"\n"                              \
        "3: orl $"__stringify(ENCLS_FAULT_FLAG)",%%eax\n"       \
        "   jmp 2b\n"                                           \
        ".previous\n"                                           \
        _ASM_EXTABLE_FAULT(1b, 3b)                              \
        : "=a"(ret), "=b"(rbx_out)                              \
        : "a"(rax), inputs                                      \
        : "memory");                                            \
        ret;                                                    \
        })

#endif //__LIME_H_
