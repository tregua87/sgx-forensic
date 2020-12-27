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

#include "lime.h"

// This file
static ssize_t write_lime_header(struct resource *);
static ssize_t write_padding(size_t);
static void write_range(struct resource *);
static int init(void);
static ssize_t write_vaddr(void *, size_t);
static ssize_t write_flush(void);
static ssize_t try_write(void *, ssize_t);
static int setup(void);
static void cleanup(void);

//SGX functions
static int detect_sgx(void);
static inline u64 sgx_extract_epc_address_size(u64 low, u64 high);
static int read_epc_bank(void * epc_bank, unsigned int epc_size);
static int write_epc_bank_lime(u64 epc_pa, u64 epc_size, void *p_last);

// External
extern ssize_t write_vaddr_tcp(void *, size_t);
extern int setup_tcp(void);
extern void cleanup_tcp(void);

extern ssize_t write_vaddr_disk(void *, size_t);
extern int setup_disk(char *, int);
extern void cleanup_disk(void);

extern int ldigest_init(void);
extern int ldigest_update(void *, size_t);
extern int ldigest_final(void);
extern int ldigest_write_tcp(void);
extern int ldigest_write_disk(void);
extern int ldigest_clean(void);

#ifdef LIME_SUPPORTS_DEFLATE
extern int deflate_begin_stream(void *, size_t);
extern int deflate_end_stream(void);
extern ssize_t deflate(const void *, size_t);
#endif

static char * format = 0;
static int mode = 0;
static int method = 0;

static void * vpage;

#ifdef LIME_SUPPORTS_DEFLATE
static void *deflate_page_buf;
#endif

char * path = 0;
int dio = 0;
int port = 0;
int localhostonly = 0;

char * digest = 0;
int compute_digest = 0;

int no_overlap = 0;

extern struct resource iomem_resource;

module_param(path, charp, S_IRUGO);
module_param(dio, int, S_IRUGO);
module_param(format, charp, S_IRUGO);
module_param(localhostonly, int, S_IRUGO);
module_param(digest, charp, S_IRUGO);

#ifdef LIME_SUPPORTS_TIMING
long timeout = 1000;
module_param(timeout, long, S_IRUGO);
#endif

#ifdef LIME_SUPPORTS_DEFLATE
int compress = 0;
module_param(compress, int, S_IRUGO);
#endif

int init_module (void)
{
    if(!path) {
        DBG("No path parameter specified");
        return -EINVAL;
    }

    if(!format) {
        DBG("No format parameter specified");
        return -EINVAL;
    }

    DBG("Parameters");
    DBG("  PATH: %s", path);
    DBG("  DIO: %u", dio);
    DBG("  FORMAT: %s", format);
    DBG("  LOCALHOSTONLY: %u", localhostonly);
    DBG("  DIGEST: %s", digest);

#ifdef LIME_SUPPORTS_TIMING
    DBG("  TIMEOUT: %lu", timeout);
#endif

#ifdef LIME_SUPPORTS_DEFLATE
    DBG("  COMPRESS: %u", compress);
#endif

    if (!strcmp(format, "raw")) mode = LIME_MODE_RAW;
    else if (!strcmp(format, "lime")) mode = LIME_MODE_LIME;
    else if (!strcmp(format, "padded")) mode = LIME_MODE_PADDED;
    else {
        DBG("Invalid format parameter specified.");
        return -EINVAL;
    }

    method = (sscanf(path, "tcp:%d", &port) == 1) ? LIME_METHOD_TCP : LIME_METHOD_DISK;
    if (digest) compute_digest = LIME_DIGEST_COMPUTE;

    return init();
}

static int init() {
    struct resource *p;
    int err = 0;
    int i;
    u32 eax, ebx, ecx, edx, type;
	u64 epc_pa, epc_size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    resource_size_t p_last = -1;
#else
    __PTRDIFF_TYPE__ p_last = -1;
#endif

    DBG("Initializing Dump...");

    if ((err = setup())) {
        DBG("Setup Error");
        cleanup();
        return err;
    }

    if (digest) {
        compute_digest = ldigest_init();
        no_overlap = 1;
    }

    vpage = (void *) __get_free_page(GFP_NOIO);

#ifdef LIME_SUPPORTS_DEFLATE
    if (compress) {
        deflate_page_buf = kmalloc(PAGE_SIZE, GFP_NOIO);
        err = deflate_begin_stream(deflate_page_buf, PAGE_SIZE);
        if (err < 0) {
            DBG("ZLIB begin stream failed");
            return err;
        }
        no_overlap = 1;
    }
#endif

    for (p = iomem_resource.child; p ; p = p->sibling) {

        if (!p->name || strcmp(p->name, LIME_RAMSTR))
            continue;

        if (mode == LIME_MODE_LIME && write_lime_header(p) < 0) {
            DBG("Error writing header 0x%lx - 0x%lx", (long) p->start, (long) p->end);
            break;
        } else if (mode == LIME_MODE_PADDED && write_padding((size_t) ((p->start - 1) - p_last)) < 0) {
            DBG("Error writing padding 0x%lx - 0x%lx", (long) p_last, (long) p->start - 1);
            break;
        }

        write_range(p);

        p_last = p->end;
    }

    // Check SGX support and dump EPC banks
    if(detect_sgx()) {
        DBG("SGX present and enabled!");

        // Loop over EPC banks and dump them
        for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
            cpuid_count(SGX_CPUID, i + SGX_CPUID_FIRST_VARIABLE_SUB_LEAF,
                    &eax, &ebx, &ecx, &edx);

            type = eax & SGX_CPUID_SUB_LEAF_TYPE_MASK;
            if (type == SGX_CPUID_SUB_LEAF_INVALID)
                break;

            if (type != SGX_CPUID_SUB_LEAF_EPC_SECTION)
                break;

            epc_pa = sgx_extract_epc_address_size(eax, ebx);
            epc_size = sgx_extract_epc_address_size(ecx, edx);

            DBG("EPC section 0x%llx-0x%llx", epc_pa, epc_pa + epc_size - 1);

            err = write_epc_bank_lime(epc_pa, epc_size, &p_last);
            memset(vpage, 0, PAGE_SIZE);
            if(err)
                break;
        }

    }

    write_flush();

    DBG("Memory Dump Complete...");

    cleanup();

    if (compute_digest == LIME_DIGEST_COMPUTE) {
        DBG("Writing Out Digest.");

        compute_digest = ldigest_final();

        if (compute_digest == LIME_DIGEST_COMPLETE) {
            if (method == LIME_METHOD_TCP)
                err = ldigest_write_tcp();
            else
                err = ldigest_write_disk();

            DBG("Digest Write %s.", (err == 0) ? "Complete" : "Failed");
        }
    }

    if (digest)
        ldigest_clean();

#ifdef LIME_SUPPORTS_DEFLATE
    if (compress) {
        deflate_end_stream();
        kfree(deflate_page_buf);
    }
#endif

    free_page((unsigned long) vpage);

    return 0;
}

static ssize_t write_lime_header(struct resource * res) {
    lime_mem_range_header header;

    memset(&header, 0, sizeof(lime_mem_range_header));
    header.magic = LIME_MAGIC;
    header.version = 1;
    header.s_addr = res->start;
    header.e_addr = res->end;

    return write_vaddr(&header, sizeof(lime_mem_range_header));
}

static ssize_t write_padding(size_t s) {
    size_t i = 0;
    ssize_t r;

    memset(vpage, 0, PAGE_SIZE);

    while(s -= i) {

        i = min((size_t) PAGE_SIZE, s);
        r = write_vaddr(vpage, i);

        if (r != i) {
            DBG("Error sending zero page: %zd", r);
            return r;
        }
    }

    return 0;
}

static void write_range(struct resource * res) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    resource_size_t i, is;
#else
    __PTRDIFF_TYPE__ i, is;
#endif
    struct page * p;
    void * v;

    ssize_t s;

#ifdef LIME_SUPPORTS_TIMING
    ktime_t start,end;
#endif

    DBG("Writing range %llx - %llx.", res->start, res->end);

    for (i = res->start; i <= res->end; i += is) {
#ifdef LIME_SUPPORTS_TIMING
        start = ktime_get_real();
#endif
        p = pfn_to_page((i) >> PAGE_SHIFT);

        is = min((size_t) PAGE_SIZE, (size_t) (res->end - i + 1));

        if (is < PAGE_SIZE) {
            // We can't map partial pages and
            // the linux kernel doesn't use them anyway
            DBG("Padding partial page: vaddr %p size: %lu", (void *) i, (unsigned long) is);
            write_padding(is);
        } else {
            v = kmap(p);
            /*
             * If we need to compute the digest or compress the output
             * take a snapshot of the page. Otherwise save some cycles.
             */
            if (no_overlap) {
                copy_page(vpage, v);
                s = write_vaddr(vpage, is);
            } else {
                s = write_vaddr(v, is);
            }
            kunmap(p);

            if (s < 0) {
                DBG("Failed to write page: vaddr %p. Skipping Range...", v);
                break;
            }
        }

#ifdef LIME_SUPPORTS_TIMING
        end = ktime_get_real();

        if (timeout > 0 && ktime_to_ms(ktime_sub(end, start)) > timeout) {
            DBG("Reading is too slow.  Skipping Range...");
            write_padding(res->end - i + 1 - is);
            break;
        }
#endif

    }
}

static ssize_t write_vaddr(void * v, size_t is) {
    ssize_t ret;

    if (compute_digest == LIME_DIGEST_COMPUTE)
        compute_digest = ldigest_update(v, is);

#ifdef LIME_SUPPORTS_DEFLATE
    if (compress) {
        /* Run deflate() on input until output buffer is not full. */
        do {
            ret = try_write(deflate_page_buf, deflate(v, is));
            if (ret < 0)
                return ret;
        } while (ret == PAGE_SIZE);
        return is;
    }
#endif

    ret = try_write(v, is);
    return ret;
}

static ssize_t write_flush(void) {
#ifdef LIME_SUPPORTS_DEFLATE
    if (compress) {
        try_write(deflate_page_buf, deflate(NULL, 0));
    }
#endif
    return 0;
}

static ssize_t try_write(void * v, ssize_t is) {
    ssize_t ret;

    if (is <= 0)
        return is;

    ret = RETRY_IF_INTERRUPTED(
        (method == LIME_METHOD_TCP) ? write_vaddr_tcp(v, is) : write_vaddr_disk(v, is)
    );

    if (ret < 0) {
        DBG("Write error: %zd", ret);
    } else if (ret != is) {
        DBG("Short write %zu instead of %zu.", ret, is);
        ret = -1;
    }

    return ret;
}

static int setup(void) {
    return (method == LIME_METHOD_TCP) ? setup_tcp() : setup_disk(path, dio);
}

static void cleanup(void) {
    return (method == LIME_METHOD_TCP) ? cleanup_tcp() : cleanup_disk();
}

void cleanup_module(void) {

}

// SGX Functions
static int detect_sgx(void) {
    unsigned long long fc;

    rdmsrl(MSR_IA32_FEAT_CTL, fc);

    if (!(fc & FEAT_CTL_LOCKED) || !(fc & FEAT_CTL_SGX_ENABLED) || !cpu_has(&boot_cpu_data, X86_FEATURE_SGX))
        return 0;
    else
        return 1;

}

static inline u64 sgx_extract_epc_address_size(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

static int read_epc_bank(void * epc_bank, unsigned int epc_size) {
    // Read an EPC zone and write it
    // Use the already allocated vpage as temporary buffer
    unsigned long epc_page_addr;
    unsigned long rd_data;
    unsigned long *rd_data_ptr = &rd_data;
    int pg_off, offset, modified;

    modified = 1;
    for (pg_off = 0; pg_off < epc_size; pg_off += PAGE_SIZE) {

        // Set the page content as an SGX abort page
        if (modified) {
            memset(vpage, 0xFF, PAGE_SIZE);
            modified = 0;
        }

        epc_page_addr = ((unsigned long) epc_bank) + pg_off;
        for (offset = 0; offset < PAGE_SIZE; offset += sizeof(unsigned long)) {
            if(!(enclave_op(EDGBRD, rd_data_ptr,  epc_page_addr + offset))) {
                memcpy(vpage + offset, rd_data_ptr, sizeof(unsigned long));
                modified = 1;
	        }
        }

        if (write_vaddr(vpage, PAGE_SIZE) < 0) {
            DBG("SGX: error writing physical page");
            return 1;
            }
     }
     return 0;
}

static int write_epc_bank_lime(u64 epc_pa, u64 epc_size, void *p_last_v) {
    void *epc_map;
    struct resource epc_resource;
    long *p_last = (long *)p_last_v;
    int status = 0;
    epc_resource.start = epc_pa;
    epc_resource.end = epc_pa + epc_size - 1;

    if (mode == LIME_MODE_LIME && write_lime_header(&epc_resource) < 0) {
        DBG("Error writing header 0x%lx - 0x%lx", (long) epc_pa, (long) epc_resource.end);
        return 1;
    }

    else if (mode == LIME_MODE_PADDED && write_padding((size_t) ((epc_pa - 1) - (*p_last))) < 0) {
        DBG("Error writing padding 0x%lx - 0x%lx", (long) (*p_last), (long) epc_pa - 1);
        return 1;
    }

    // Dump SGX pages in EPC bank
    epc_map = memremap(epc_pa, epc_size, MEMREMAP_WB);
    if (epc_map) {
        status = read_epc_bank(epc_map, epc_size);
        memunmap(epc_map);
    }
    else
        DBG("Error in memremap() of 0x%lx - 0x%lx EPC bank", (long) epc_pa, (long) epc_resource.end);

    *p_last = epc_resource.end;

    return status;
}

MODULE_LICENSE("GPL");
