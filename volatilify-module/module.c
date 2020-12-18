/*
  This module does absolutely nothings at all. We just build it with debugging
symbols and then read the DWARF symbols from it.
*/
#include <linux/module.h>
#include <linux/version.h>

#include <linux/mmu_notifier.h>
#include <linux/ioport.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/udp.h>
#include <linux/mount.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
struct xa_node xa;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#include <linux/lockref.h>
struct lockref lockref;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>
#else
#include <linux/file.h>
#endif

#include <net/ip_fib.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/pid.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/pid_namespace.h>
struct pid_namespace pid_namespace;
#endif


#ifdef CONFIG_NETFILTER
#include <linux/netfilter.h>

struct nf_hook_ops nf_hook_ops;
struct nf_sockopt_ops nf_sockopt_ops;

#ifdef CONFIG_NETFILTER_XTABLES
#include <linux/netfilter/x_tables.h>
struct xt_table xt_table;
#endif

#endif

#include <linux/radix-tree.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <linux/termios.h>
#include <asm/termbits.h>

#include <linux/notifier.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
struct atomic_notifier_head atomic_notifier_head;
#endif

#include <linux/tty_driver.h>
struct tty_driver tty_driver;

#include <linux/tty.h>
struct tty_struct tty_struct;

struct udp_seq_afinfo udp_seq_afinfo;
struct tcp_seq_afinfo tcp_seq_afinfo;

struct files_struct files_struct;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
struct uts_namespace uts_namespace;
#endif

struct sock sock;
struct inet_sock inet_sock;
struct vfsmount vfsmount;
struct in_device in_device;
struct fib_table fib_table;
struct unix_sock unix_sock;
struct pid pid;
struct radix_tree_root radix_tree_root;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#ifdef CONFIG_NET_SCHED
#include <net/sch_generic.h>
struct Qdisc qdisc;
#endif
#endif

struct inet_protosw inet_protosw;

/********************************************************************
The following structs are not defined in headers, so we cant import
them. Hopefully they dont change too much.
*********************************************************************/

struct kthread_create_info
{
     /* Information passed to kthread() from kthreadd. */
     int (*threadfn)(void *data);
     void *data;
     int node;

     /* Result passed back to kthread_create() from kthreadd. */
     struct task_struct *result;
     struct completion done;

     struct list_head list;
};

struct kthread_create_info kthread_create_info;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

#include <net/ip.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <linux/compiler.h>

#define EMBEDDED_HASH_SIZE (L1_CACHE_BYTES / sizeof(struct hlist_head))

#define __rcu

struct fn_zone {
  struct fn_zone     *fz_next;       /* Next not empty zone  */
  struct hlist_head  *fz_hash;       /* Hash table pointer   */
  seqlock_t               fz_lock;
  u32                     fz_hashmask;    /* (fz_divisor - 1)     */
  u8                      fz_order;       /* Zone order (0..32)   */
  u8                      fz_revorder;    /* 32 - fz_order        */
  __be32                  fz_mask;        /* inet_make_mask(order) */

  struct hlist_head       fz_embedded_hash[EMBEDDED_HASH_SIZE];

  int                     fz_nent;        /* Number of entries    */
  int                     fz_divisor;     /* Hash size (mask+1)   */
} fn_zone;

struct fn_hash {
  struct fn_zone    *fn_zones[33];
  struct fn_zone    *fn_zone_list;
} fn_hash;

struct fib_alias 
{
    struct list_head        fa_list;
    struct fib_info         *fa_info;
    u8                      fa_tos;
    u8                      fa_type;
    u8                      fa_scope;
    u8                      fa_state;
#ifdef CONFIG_IP_FIB_TRIE
        struct rcu_head         rcu;
#endif
};

struct fib_node 
{
    struct hlist_node       fn_hash;
    struct list_head        fn_alias;
    __be32                  fn_key;
    struct fib_alias        fn_embedded_alias;
};


struct fib_node fib_node;
struct fib_alias fib_alias;

struct rt_hash_bucket {
  struct rtable __rcu     *chain;
} rt_hash_bucket;

#ifndef RADIX_TREE_MAP_SHIFT

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define RADIX_TREE_MAP_SHIFT    6
#else
#define RADIX_TREE_MAP_SHIFT    (CONFIG_BASE_SMALL ? 4 : 6)
#endif
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)
#define RADIX_TREE_TAG_LONGS    ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define RADIX_TREE_MAX_TAGS     2

struct radix_tree_node {
    unsigned int    height;         /* Height from the bottom */
    unsigned int    count;
    struct rcu_head rcu_head;
    void            *slots[RADIX_TREE_MAP_SIZE];
    unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define OUR_OWN_MOD_STRUCTS
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#define OUR_OWN_MOD_STRUCTS
#endif

#ifdef OUR_OWN_MOD_STRUCTS
struct module_sect_attr
{
        struct module_attribute mattr;
        char *name;
        unsigned long address;
};

struct module_sect_attrs
{
        struct attribute_group grp;
        unsigned int nsections;
        struct module_sect_attr attrs[0];
};

struct module_sect_attrs module_sect_attrs;

#else

struct module_sections module_sect_attrs;

#endif

struct module_kobject module_kobject;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
// we can't get the defintion of mod_tree_root directly
// because it is declared in module.c as a static struct
// the latch_tree_root struct has the variables we want 
// immediately after it though

#include <linux/rbtree_latch.h>

struct latch_tree_root ltr;

#endif

#ifdef CONFIG_SLAB

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/*
 * struct kmem_cache
 *
 * manages a cache.
 */

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
	struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	unsigned int buffer_size;
	u32 reciprocal_buffer_size;
/* 3) touched by every alloc & free from the backend */

	unsigned int flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 4) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t gfpflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *slabp_cache;
	unsigned int slab_size;
	unsigned int dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(void *obj);

/* 5) cache creation/removal */
	const char *name;
	struct list_head next;

/* 6) statistics */
#if STATS
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;
#endif
#if DEBUG
	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. buffer_size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
	int obj_size;
#endif
	/*
	 * We put nodelists[] at the end of kmem_cache, because we want to size
	 * this array to nr_node_ids slots instead of MAX_NUMNODES
	 * (see kmem_cache_init())
	 * We still use [MAX_NUMNODES] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of nodes.
	 */
	struct kmem_list3 *nodelists[MAX_NUMNODES];
	/*
	 * Do not add fields after nodelists[]
	 */
};
#else

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
        struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
        unsigned int batchcount;
        unsigned int limit;
        unsigned int shared;

        unsigned int buffer_size;
/* 3) touched by every alloc & free from the backend */
        struct kmem_list3 *nodelists[MAX_NUMNODES];

        unsigned int flags;             /* constant flags */
        unsigned int num;               /* # of objs per slab */

/* 4) cache_grow/shrink */
        /* order of pgs per slab (2^n) */
        unsigned int gfporder;

        /* force GFP flags, e.g. GFP_DMA */
        gfp_t gfpflags;

        size_t colour;                  /* cache colouring range */
        unsigned int colour_off;        /* colour offset */
        struct kmem_cache *slabp_cache;
        unsigned int slab_size;
        unsigned int dflags;            /* dynamic flags */

        /* constructor func */
        void (*ctor) (void *, struct kmem_cache *, unsigned long);

        /* de-constructor func */
        void (*dtor) (void *, struct kmem_cache *, unsigned long);

/* 5) cache creation/removal */
        const char *name;
        struct list_head next;

/* 6) statistics */
#if STATS
        unsigned long num_active;
        unsigned long num_allocations;
        unsigned long high_mark;
        unsigned long grown;
        unsigned long reaped;
        unsigned long errors;
        unsigned long max_freeable;
        unsigned long node_allocs;
        unsigned long node_frees;
        unsigned long node_overflow;
        atomic_t allochit;
        atomic_t allocmiss;
        atomic_t freehit;
        atomic_t freemiss;
#endif
#if DEBUG
        /*
         * If debugging is enabled, then the allocator can add additional
         * fields and/or padding to every object. buffer_size contains the total
         * object size including these internal fields, the following two
         * variables contain the offset to the user object and its size.
         */
        int obj_offset;
        int obj_size;
#endif
};

#endif /*kmem_cache decl*/

struct kmem_cache kmem_cache;
#endif

struct kmem_list3 {
         struct list_head slabs_partial; /* partial list first, better asm code */
         struct list_head slabs_full;
         struct list_head slabs_free;
        unsigned long free_objects;
         unsigned int free_limit;
         unsigned int colour_next;       /* Per-node cache coloring */
         spinlock_t list_lock;
         struct array_cache *shared;     /* shared per node */
         struct array_cache **alien;     /* on other nodes */
         unsigned long next_reap;        /* updated without locking */
         int free_touched;               /* updated without locking */
};

struct kmem_list3 kmem_list3;

struct slab {         
     struct list_head list;
     unsigned long colouroff;
     void *s_mem;            /* including colour offset */
     unsigned int inuse;     /* num of objs active in slab */
     unsigned int free;
     unsigned short nodeid;          
 };
 
struct slab slab;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
/* Starting with Linux kernel 3.7 the struct timekeeper is defined in include/linux/timekeeper_internal.h */
#include <linux/timekeeper_internal.h>
#else
/* Before Linux kernel 3.7 the struct timekeeper has to be taken from kernel/time/timekeeping.c */

typedef u64 cycle_t;

struct timekeeper {
	/* Current clocksource used for timekeeping. */
	struct clocksource *clock;
	/* NTP adjusted clock multiplier */
	u32	mult;
	/* The shift value of the current clocksource. */
	int	shift;

	/* Number of clock cycles in one NTP interval. */
	cycle_t cycle_interval;
	/* Number of clock shifted nano seconds in one NTP interval. */
	u64	xtime_interval;
	/* shifted nano seconds left over when rounding cycle_interval */
	s64	xtime_remainder;
	/* Raw nano seconds accumulated per NTP interval. */
	u32	raw_interval;

	/* Clock shifted nano seconds remainder not stored in xtime.tv_nsec. */
	u64	xtime_nsec;
	/* Difference between accumulated time and NTP time in ntp
	 * shifted nano seconds. */
	s64	ntp_error;
	/* Shift conversion between clock shifted nano seconds and
	 * ntp shifted nano seconds. */
	int	ntp_error_shift;

	/* The current time */
	struct timespec xtime;
	/*
	 * wall_to_monotonic is what we need to add to xtime (or xtime corrected
	 * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
	 * at zero at system boot time, so wall_to_monotonic will be negative,
	 * however, we will ALWAYS keep the tv_nsec part positive so we can use
	 * the usual normalization.
	 *
	 * wall_to_monotonic is moved after resume from suspend for the
	 * monotonic time not to jump. We need to add total_sleep_time to
	 * wall_to_monotonic to get the real boot based time offset.
	 *
	 * - wall_to_monotonic is no longer the boot time, getboottime must be
	 * used instead.
	 */
	struct timespec wall_to_monotonic;
	/* time spent in suspend */
	struct timespec total_sleep_time;
	/* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
	struct timespec raw_time;

	/* Offset clock monotonic -> clock realtime */
	ktime_t offs_real;

	/* Offset clock monotonic -> clock boottime */
	ktime_t offs_boot;

	/* Seqlock for all timekeeper values */
	seqlock_t lock;
};

#endif

struct timekeeper my_timekeeper;

struct log {
         u64 ts_nsec;            /* timestamp in nanoseconds */
         u16 len;                /* length of entire record */
         u16 text_len;           /* length of text buffer */
         u16 dict_len;           /* length of dictionary buffer */
         u8 facility;            /* syslog facility */
         u8 flags:5;             /* internal record flags */
         u8 level:3;             /* syslog level */
};

struct log my_log;

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)

struct mnt_namespace {
	atomic_t		count;
	struct mount *	root;
	struct list_head	list;
	wait_queue_head_t poll;
	int event;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mount {
	struct list_head mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
        struct callback_head rcu;
#endif
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_t mnt_longterm;		/* how many of the refs are longterm */
#endif
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
	int mnt_ghosts;
};

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
    struct proc_dir_entry {
        unsigned int low_ino;
        umode_t mode;
        nlink_t nlink;
        kuid_t uid;
        kgid_t gid;
        loff_t size;
        const struct inode_operations *proc_iops;
        const struct file_operations *proc_fops;
        struct proc_dir_entry *next, *parent, *subdir;
        void *data;
        atomic_t count;         /* use count */
        atomic_t in_use;        /* number of callers into module in progress; */
                              /* negative -> it's going away RSN */
        struct completion *pde_unload_completion;
        struct list_head pde_openers;   /* who did ->open, but not ->release */
        spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
        u8 namelen;
        char name[];
    };
#else
   struct proc_dir_entry {
        unsigned int low_ino;
        umode_t mode;
        nlink_t nlink;
        kuid_t uid;
        kgid_t gid;
        loff_t size;
        const struct inode_operations *proc_iops;
        const struct file_operations *proc_fops;
        struct proc_dir_entry *parent;
        struct rb_root subdir;
        struct rb_node subdir_node;
        void *data;
        atomic_t count;     /* use count */
        atomic_t in_use;    /* number of callers into module in progress; */
                /* negative -> it's going away RSN */
        struct completion *pde_unload_completion;
        struct list_head pde_openers;   /* who did ->open, but not ->release */
        spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
        u8 namelen;
        char name[];
   };
#endif
#endif

struct resource resource;

// Intel SGX drivers datastructures
#define SGX_TCS_RESERVED_SIZE 4024
#define SGX_PCMD_RESERVED_SIZE 40
#define SGX_MODULUS_SIZE 384
#define SGX_VA_SLOT_COUNT 512

// Structures common to isgx and DCAP drivers
struct sgx_secs {
        u64 size;
        u64 base;
        u32 ssa_frame_size;
        u32 miscselect;
        u8  reserved1[24];
        u64 attributes;
        u64 xfrm;
        u32 mrenclave[8];
        u8  reserved2[32];
        u32 mrsigner[8];
        u8  reserved3[32];
        u32 config_id[16];
        u16 isv_prod_id;
        u16 isv_svn;
        u16 config_svn;
        u8  reserved4[3834];
} __packed sgx_secs;

struct sgx_tcs {
        u64 state;
        u64 flags;
        u64 ssa_offset;
        u32 ssa_index;
        u32 nr_ssa_frames;
        u64 entry_offset;
        u64 exit_addr;
        u64 fs_offset;
        u64 gs_offset;
        u32 fs_limit;
        u32 gs_limit;
        u8  reserved[SGX_TCS_RESERVED_SIZE];
} __packed sgx_tcs;

struct sgx_pageinfo {
        u64 addr;
        u64 contents;
        u64 metadata;
        u64 secs;
} __packed __aligned(32) sgx_pageinfo;

struct sgx_secinfo {
        u64 flags;
        u8  reserved[56];
} __packed __aligned(64) sgx_secinfo;

struct sgx_pcmd {
        struct sgx_secinfo secinfo;
        u64 enclave_id;
        u8  reserved[SGX_PCMD_RESERVED_SIZE];
        u8  mac[16];
} __packed __aligned(128) sgx_pcmd;

struct sgx_sigstruct_header {
        u64 header1[2];
        u32 vendor;
        u32 date;
        u64 header2[2];
        u32 swdefined;
        u8  reserved1[84];
} __packed sgx_sigstruct_header;

struct sgx_sigstruct_body {
        u32 miscselect;
        u32 misc_mask;
        u8  reserved2[20];
        u64 attributes;
        u64 xfrm;
        u64 attributes_mask;
        u64 xfrm_mask;
        u8  mrenclave[32];
        u8  reserved3[32];
        u16 isvprodid;
        u16 isvsvn;
} __packed sgx_sigstruct_body;

struct sgx_sigstruct {
        struct sgx_sigstruct_header header;
        u8  modulus[SGX_MODULUS_SIZE];
        u32 exponent;
        u8  signature[SGX_MODULUS_SIZE];
        struct sgx_sigstruct_body body;
        u8  reserved4[12];
        u8  q1[SGX_MODULUS_SIZE];
        u8  q2[SGX_MODULUS_SIZE];
} __packed sgx_sigstruct;

struct sgx_enclave_create  {
        __u64   src;
} sgx_enclave_create;

// Structures which differ between isgx and DCAP driver
struct sgx_encl_page_isgx {
        unsigned long addr;
        unsigned int flags;
        struct sgx_epc_page_isgx *epc_page;
        struct sgx_va_page_isgx *va_page;
        unsigned int va_offset;
} sgx_encl_page_isgx;

struct sgx_encl_page_dcap {
        unsigned long desc;
        unsigned long vm_max_prot_bits;
        struct sgx_epc_page_dcap *epc_page;
        struct sgx_va_page_dcap *va_page;
        struct sgx_encl_dcap *encl;
} sgx_encl_page_dcap;

struct sgx_encl_isgx {
        unsigned int flags;
        uint64_t attributes;
        uint64_t xfrm;
        unsigned int secs_child_cnt;
        struct mutex lock;
        struct mm_struct *mm;
        struct file *backing;
        struct file *pcmd;
        struct list_head load_list;
        struct kref refcount;
        unsigned long base;
        unsigned long size;
        unsigned long ssaframesize;
        struct list_head va_pages;
        struct radix_tree_root page_tree;
        struct list_head add_page_reqs;
        struct work_struct add_page_work;
        struct sgx_encl_page_isgx secs;
        struct sgx_tgid_ctx *tgid_ctx;
        struct list_head encl_list;
        struct mmu_notifier mmu_notifier;
        unsigned int shadow_epoch;
} sgx_encl_isgx;

struct sgx_encl_dcap {
        atomic_t flags;
        u64 secs_attributes;
        u64 allowed_attributes;
        unsigned int page_cnt;
        unsigned int secs_child_cnt;
        struct mutex lock;
        struct list_head mm_list;
        spinlock_t mm_lock;
        unsigned long mm_list_version;
        struct file *backing;
        struct kref refcount;
        struct srcu_struct srcu;
        unsigned long base;
        unsigned long size;
        unsigned long ssaframesize;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
        struct xarray page_array;
#else
        struct radix_tree_root page_tree;
#endif
        struct list_head va_pages;
        struct sgx_encl_page_dcap secs;
        cpumask_t cpumask;
} sgx_encl_dcap;

struct sgx_va_page_isgx {
        struct sgx_epc_page_isgx *epc_page;
        DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
        struct list_head list;
} sgx_va_page_isgx;

struct sgx_va_page_dcap {
        struct sgx_epc_page_dcap *epc_page;
        DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
        struct list_head list;
} sgx_va_page_dcap;

struct sgx_epc_page_isgx {
        resource_size_t pa;
        struct list_head list;
        struct sgx_encl_page_isgx *encl_page;
} sgx_epc_page_isgx;

struct sgx_epc_page_dcap {
        unsigned long desc;
        struct sgx_encl_page_dcap *owner;
        struct list_head list;
} sgx_epc_page_dcap;

struct sgx_enclave_init_isgx {
        __u64   addr;
        __u64   sigstruct;
        __u64   einittoken;
} __attribute__((__packed__)) sgx_enclave_init_isgx;

struct sgx_enclave_init_dcap {
        __u64 sigstruct;
} sgx_enclave_init_dcap;

//Structures used only by DCAP driver
struct sgx_encl_mm {
        struct sgx_encl_dcap *encl;
        struct mm_struct *mm;
        struct list_head list;
        struct mmu_notifier mmu_notifier;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
        struct rcu_head rcu;
#endif
} sgx_encl_mm;

struct sgx_backing {
        pgoff_t page_index;
        struct page *contents;
        struct page *pcmd;
        unsigned long pcmd_offset;
} sgx_backing;

struct sgx_epc_section {
        unsigned long pa;
        void *va;
        unsigned long free_cnt;
        struct list_head page_list;
        struct list_head unsanitized_page_list;
        spinlock_t lock;
} sgx_epc_section;

struct sgx_enclave_add_pages {
        __u64   src;
        __u64   offset;
        __u64   length;
        __u64   secinfo;
        __u64   flags;
        __u64   count;
} sgx_enclave_add_pages;

struct sgx_enclave_set_attribute {
        __u64 attribute_fd;
};

struct sgx_enclave_exception {
        __u32 leaf;
        __u16 trapnr;
        __u16 error_code;
        __u64 address;
        __u64 reserved[2];
} sgx_enclave_exception;

// Structures used only by isgx driver
struct sgx_sigstruct_payload {
        struct sgx_sigstruct_header header;
        struct sgx_sigstruct_body body;
} sgx_sigstruct_payload;

struct sgx_einittoken_payload {
        uint32_t valid;
        uint32_t reserved1[11];
        uint64_t attributes;
        uint64_t xfrm;
        uint8_t mrenclave[32];
        uint8_t reserved2[32];
        uint8_t mrsigner[32];
        uint8_t reserved3[32];
} sgx_einittoken_payload;

struct sgx_einittoken {
        struct sgx_einittoken_payload payload;
        uint8_t cpusvnle[16];
        uint16_t isvprodidle;
        uint16_t isvsvnle;
        uint8_t reserved2[24];
        uint32_t maskedmiscselectle;
        uint64_t maskedattributesle;
        uint64_t maskedxfrmle;
        uint8_t keyid[32];
        uint8_t mac[16];
} sgx_einittoken;

struct sgx_report {
        uint8_t cpusvn[16];
        uint32_t miscselect;
        uint8_t reserved1[28];
        uint64_t attributes;
        uint64_t xfrm;
        uint8_t mrenclave[32];
        uint8_t reserved2[32];
        uint8_t mrsigner[32];
        uint8_t reserved3[96];
        uint16_t isvprodid;
        uint16_t isvsvn;
        uint8_t reserved4[60];
        uint8_t reportdata[64];
        uint8_t keyid[32];
        uint8_t mac[16];
} sgx_report;

struct sgx_targetinfo {
        uint8_t mrenclave[32];
        uint64_t attributes;
        uint64_t xfrm;
        uint8_t reserved1[4];
        uint32_t miscselect;
        uint8_t reserved2[456];
} sgx_targetinfo;

struct sgx_keyrequest {
        uint16_t keyname;
        uint16_t keypolicy;
        uint16_t isvsvn;
        uint16_t reserved1;
        uint8_t cpusvn[16];
        uint64_t attributemask;
        uint64_t xfrmmask;
        uint8_t keyid[32];
        uint32_t miscmask;
        uint8_t reserved2[436];
} sgx_keyrequest;

struct sgx_tgid_ctx {
        struct pid *tgid;
        struct kref refcount;
        struct list_head encl_list;
        struct list_head list;
} sgx_tgid_ctx;

struct sgx_epc_bank {
        unsigned long pa;
#ifdef CONFIG_X86_64
        unsigned long va;
#endif
        unsigned long size;
} sgx_epc_bank;

struct sgx_enclave_add_page {
        __u64   addr;
        __u64   src;
        __u64   secinfo;
        __u16   mrmask;
} __attribute__((__packed__)) sgx_enclave_add_page;

struct sgx_range {
        unsigned long start_addr;
        unsigned int nr_pages;
} sgx_range;

struct sgx_modification_param {
        struct sgx_range range;
        unsigned long flags;
} sgx_modification_param;