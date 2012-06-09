#define SBLOCK_FLOPPY        0
   69 #define SBLOCK_UFS1       8192
   70 #define SBLOCK_UFS2      65536
   71 #define SBLOCK_PIGGY    262144
   72 #define SBLOCKSIZE        8192
   73 #define SBLOCKSEARCH \
   74         { SBLOCK_UFS2, SBLOCK_UFS1, SBLOCK_FLOPPY, SBLOCK_PIGGY, -1 }
   75 
   76 /*
   77  * Max number of fragments per block. This value is NOT tweakable.
   78  */
   79 #define MAXFRAG         8
   80 
   81 /*
   82  * Addresses stored in inodes are capable of addressing fragments
   83  * of `blocks'. File system blocks of at most size MAXBSIZE can
   84  * be optionally broken into 2, 4, or 8 pieces, each of which is
   85  * addressable; these pieces may be DEV_BSIZE, or some multiple of
   86  * a DEV_BSIZE unit.
   87  *
   88  * Large files consist of exclusively large data blocks.  To avoid
   89  * undue wasted disk space, the last data block of a small file may be
   90  * allocated as only as many fragments of a large block as are
   91  * necessary.  The filesystem format retains only a single pointer
   92  * to such a fragment, which is a piece of a single large block that
   93  * has been divided.  The size of such a fragment is determinable from
   94  * information in the inode, using the ``blksize(fs, ip, lbn)'' macro.
   95  *
   96  * The filesystem records space availability at the fragment level;
   97  * to determine block availability, aligned fragments are examined.
   98  */
   99 
  100 /*
  101  * MINBSIZE is the smallest allowable block size.
  102  * In order to insure that it is possible to create files of size
  103  * 2^32 with only two levels of indirection, MINBSIZE is set to 4096.
  104  * MINBSIZE must be big enough to hold a cylinder group block,
  105  * thus changes to (struct cg) must keep its size within MINBSIZE.
  106  * Note that super blocks are always of size SBSIZE,
  107  * and that both SBSIZE and MAXBSIZE must be >= MINBSIZE.
  108  */
  109 #define MINBSIZE        4096
  110 
  111 /*
  112  * The path name on which the filesystem is mounted is maintained
  113  * in fs_fsmnt. MAXMNTLEN defines the amount of space allocated in
  114  * the super block for this name.
  115  */
  116 #define MAXMNTLEN       468
  117 
  118 /*
  119  * The volume name for this filesystem is maintained in fs_volname.
  120  * MAXVOLLEN defines the length of the buffer allocated.
  121  */
  122 #define MAXVOLLEN       32
  123 
  124 /*
  125  * There is a 128-byte region in the superblock reserved for in-core
  126  * pointers to summary information. Originally this included an array
  127  * of pointers to blocks of struct csum; now there are just a few
  128  * pointers and the remaining space is padded with fs_ocsp[].
  129  *
  130  * NOCSPTRS determines the size of this padding. One pointer (fs_csp)
  131  * is taken away to point to a contiguous array of struct csum for
  132  * all cylinder groups; a second (fs_maxcluster) points to an array
  133  * of cluster sizes that is computed as cylinder groups are inspected,
  134  * and the third points to an array that tracks the creation of new
  135  * directories. A fourth pointer, fs_active, is used when creating
  136  * snapshots; it points to a bitmap of cylinder groups for which the
  137  * free-block bitmap has changed since the snapshot operation began.
  138  */
  139 #define NOCSPTRS        ((128 / sizeof(void *)) - 4)
  140 
  141 /*
  142  * A summary of contiguous blocks of various sizes is maintained
  143  * in each cylinder group. Normally this is set by the initial
  144  * value of fs_maxcontig. To conserve space, a maximum summary size
  145  * is set by FS_MAXCONTIG.
  146  */
  147 #define FS_MAXCONTIG    16
  148 
  149 /*
  150  * MINFREE gives the minimum acceptable percentage of filesystem
  151  * blocks which may be free. If the freelist drops below this level
  152  * only the superuser may continue to allocate blocks. This may
  153  * be set to 0 if no reserve of free blocks is deemed necessary,
  154  * however throughput drops by fifty percent if the filesystem
  155  * is run at between 95% and 100% full; thus the minimum default
  156  * value of fs_minfree is 5%. However, to get good clustering
  157  * performance, 10% is a better choice. hence we use 10% as our
  158  * default value. With 10% free space, fragmentation is not a
  159  * problem, so we choose to optimize for time.
  160  */
  161 #define MINFREE         8
  162 #define DEFAULTOPT      FS_OPTTIME
  163 
  164 /*
  165  * Grigoriy Orlov <gluk@ptci.ru> has done some extensive work to fine
  166  * tune the layout preferences for directories within a filesystem.
  167  * His algorithm can be tuned by adjusting the following parameters
  168  * which tell the system the average file size and the average number
  169  * of files per directory. These defaults are well selected for typical
  170  * filesystems, but may need to be tuned for odd cases like filesystems
  171  * being used for squid caches or news spools.
  172  */
  173 #define AVFILESIZ       16384   /* expected average file size */
  174 #define AFPDIR          64      /* expected number of files per directory */
  175 
  176 /*
  177  * The maximum number of snapshot nodes that can be associated
  178  * with each filesystem. This limit affects only the number of
  179  * snapshot files that can be recorded within the superblock so
  180  * that they can be found when the filesystem is mounted. However,
  181  * maintaining too many will slow the filesystem performance, so
  182  * having this limit is a good idea.
  183  */
  184 #define FSMAXSNAP 20
  185 
  186 /*
  187  * Used to identify special blocks in snapshots:
  188  *
  189  * BLK_NOCOPY - A block that was unallocated at the time the snapshot
  190  *      was taken, hence does not need to be copied when written.
  191  * BLK_SNAP - A block held by another snapshot that is not needed by this
  192  *      snapshot. When the other snapshot is freed, the BLK_SNAP entries
  193  *      are converted to BLK_NOCOPY. These are needed to allow fsck to
  194  *      identify blocks that are in use by other snapshots (which are
  195  *      expunged from this snapshot).
  196  */
  197 #define BLK_NOCOPY ((ufs2_daddr_t)(1))
  198 #define BLK_SNAP ((ufs2_daddr_t)(2))
  199 
  200 /*
  201  * Sysctl values for the fast filesystem.
  202  */
  203 #define FFS_ADJ_REFCNT           1      /* adjust inode reference count */
  204 #define FFS_ADJ_BLKCNT           2      /* adjust inode used block count */
  205 #define FFS_BLK_FREE             3      /* free range of blocks in map */
  206 #define FFS_DIR_FREE             4      /* free specified dir inodes in map */
  207 #define FFS_FILE_FREE            5      /* free specified file inodes in map */
  208 #define FFS_SET_FLAGS            6      /* set filesystem flags */
  209 #define FFS_ADJ_NDIR             7      /* adjust number of directories */
  210 #define FFS_ADJ_NBFREE           8      /* adjust number of free blocks */
  211 #define FFS_ADJ_NIFREE           9      /* adjust number of free inodes */
  212 #define FFS_ADJ_NFFREE          10      /* adjust number of free frags */
  213 #define FFS_ADJ_NUMCLUSTERS     11      /* adjust number of free clusters */
  214 #define FFS_MAXID               12      /* number of valid ffs ids */
  215 
  216 /*
  217  * Command structure passed in to the filesystem to adjust filesystem values.
  218  */
  219 #define FFS_CMD_VERSION         0x19790518      /* version ID */
  220 struct fsck_cmd {
  221         int32_t version;        /* version of command structure */
  222         int32_t handle;         /* reference to filesystem to be changed */
  223         int64_t value;          /* inode or block number to be affected */
  224         int64_t size;           /* amount or range to be adjusted */
  225         int64_t spare;          /* reserved for future use */
  226 };
  227 
  228 /*
  229  * Per cylinder group information; summarized in blocks allocated
  230  * from first cylinder group data blocks.  These blocks have to be
  231  * read in from fs_csaddr (size fs_cssize) in addition to the
  232  * super block.
  233  */
  234 struct csum {
  235         int32_t cs_ndir;                /* number of directories */
  236         int32_t cs_nbfree;              /* number of free blocks */
  237         int32_t cs_nifree;              /* number of free inodes */
  238         int32_t cs_nffree;              /* number of free frags */
  239 };
  240 struct csum_total {
  241         int64_t cs_ndir;                /* number of directories */
  242         int64_t cs_nbfree;              /* number of free blocks */
  243         int64_t cs_nifree;              /* number of free inodes */
  244         int64_t cs_nffree;              /* number of free frags */
  245         int64_t cs_numclusters;         /* number of free clusters */
  246         int64_t cs_spare[3];            /* future expansion */
  247 };
  248 
  249 /*
  250  * Super block for an FFS filesystem.
  251  */
  252 struct fs {
  253         int32_t  fs_firstfield;         /* historic filesystem linked list, */
  254         int32_t  fs_unused_1;           /*     used for incore super blocks */
  255         int32_t  fs_sblkno;             /* offset of super-block in filesys */
  256         int32_t  fs_cblkno;             /* offset of cyl-block in filesys */
  257         int32_t  fs_iblkno;             /* offset of inode-blocks in filesys */
  258         int32_t  fs_dblkno;             /* offset of first data after cg */
  259         int32_t  fs_old_cgoffset;       /* cylinder group offset in cylinder */
  260         int32_t  fs_old_cgmask;         /* used to calc mod fs_ntrak */
  261         int32_t  fs_old_time;           /* last time written */
  262         int32_t  fs_old_size;           /* number of blocks in fs */
  263         int32_t  fs_old_dsize;          /* number of data blocks in fs */
  264         int32_t  fs_ncg;                /* number of cylinder groups */
  265         int32_t  fs_bsize;              /* size of basic blocks in fs */
  266         int32_t  fs_fsize;              /* size of frag blocks in fs */
  267         int32_t  fs_frag;               /* number of frags in a block in fs */
  268 /* these are configuration parameters */
  269         int32_t  fs_minfree;            /* minimum percentage of free blocks */
  270         int32_t  fs_old_rotdelay;       /* num of ms for optimal next block */
  271         int32_t  fs_old_rps;            /* disk revolutions per second */
  272 /* these fields can be computed from the others */
  273         int32_t  fs_bmask;              /* ``blkoff'' calc of blk offsets */
  274         int32_t  fs_fmask;              /* ``fragoff'' calc of frag offsets */
  275         int32_t  fs_bshift;             /* ``lblkno'' calc of logical blkno */
  276         int32_t  fs_fshift;             /* ``numfrags'' calc number of frags */
  277 /* these are configuration parameters */
  278         int32_t  fs_maxcontig;          /* max number of contiguous blks */
  279         int32_t  fs_maxbpg;             /* max number of blks per cyl group */
  280 /* these fields can be computed from the others */
  281         int32_t  fs_fragshift;          /* block to frag shift */
  282         int32_t  fs_fsbtodb;            /* fsbtodb and dbtofsb shift constant */
  283         int32_t  fs_sbsize;             /* actual size of super block */
  284         int32_t  fs_spare1[2];          /* old fs_csmask */
  285                                         /* old fs_csshift */
  286         int32_t  fs_nindir;             /* value of NINDIR */
  287         int32_t  fs_inopb;              /* value of INOPB */
  288         int32_t  fs_old_nspf;           /* value of NSPF */
  289 /* yet another configuration parameter */
  290         int32_t  fs_optim;              /* optimization preference, see below */
  291         int32_t  fs_old_npsect;         /* # sectors/track including spares */
  292         int32_t  fs_old_interleave;     /* hardware sector interleave */
  293         int32_t  fs_old_trackskew;      /* sector 0 skew, per track */
  294         int32_t  fs_id[2];              /* unique filesystem id */
  295 /* sizes determined by number of cylinder groups and their sizes */
  296         int32_t  fs_old_csaddr;         /* blk addr of cyl grp summary area */
  297         int32_t  fs_cssize;             /* size of cyl grp summary area */
  298         int32_t  fs_cgsize;             /* cylinder group size */
  299         int32_t  fs_spare2;             /* old fs_ntrak */
  300         int32_t  fs_old_nsect;          /* sectors per track */
  301         int32_t  fs_old_spc;            /* sectors per cylinder */
  302         int32_t  fs_old_ncyl;           /* cylinders in filesystem */
  303         int32_t  fs_old_cpg;            /* cylinders per group */
  304         int32_t  fs_ipg;                /* inodes per group */
  305         int32_t  fs_fpg;                /* blocks per group * fs_frag */
  306 /* this data must be re-computed after crashes */
  307         struct  csum fs_old_cstotal;    /* cylinder summary information */
  308 /* these fields are cleared at mount time */
  309         int8_t   fs_fmod;               /* super block modified flag */
  310         int8_t   fs_clean;              /* filesystem is clean flag */
  311         int8_t   fs_ronly;              /* mounted read-only flag */
  312         int8_t   fs_old_flags;          /* old FS_ flags */
  313         u_char   fs_fsmnt[MAXMNTLEN];   /* name mounted on */
  314         u_char   fs_volname[MAXVOLLEN]; /* volume name */
  315         u_int64_t fs_swuid;             /* system-wide uid */
  316         int32_t  fs_pad;                /* due to alignment of fs_swuid */
  317 /* these fields retain the current block allocation info */
  318         int32_t  fs_cgrotor;            /* last cg searched */
  319         void    *fs_ocsp[NOCSPTRS];     /* padding; was list of fs_cs buffers */
  320         u_int8_t *fs_contigdirs;        /* (u) # of contig. allocated dirs */
  321         struct  csum *fs_csp;           /* (u) cg summary info buffer */
  322         int32_t *fs_maxcluster;         /* (u) max cluster in each cyl group */
  323         u_int   *fs_active;             /* (u) used by snapshots to track fs */
  324         int32_t  fs_old_cpc;            /* cyl per cycle in postbl */
  325         int32_t  fs_maxbsize;           /* maximum blocking factor permitted */
  326         int64_t  fs_sparecon64[17];     /* old rotation block list head */
  327         int64_t  fs_sblockloc;          /* byte offset of standard superblock */
  328         struct  csum_total fs_cstotal;  /* (u) cylinder summary information */
  329         ufs_time_t fs_time;             /* last time written */
  330         int64_t  fs_size;               /* number of blocks in fs */
  331         int64_t  fs_dsize;              /* number of data blocks in fs */
  332         ufs2_daddr_t fs_csaddr;         /* blk addr of cyl grp summary area */
  333         int64_t  fs_pendingblocks;      /* (u) blocks being freed */
  334         int32_t  fs_pendinginodes;      /* (u) inodes being freed */
  335         int32_t  fs_snapinum[FSMAXSNAP];/* list of snapshot inode numbers */
  336         int32_t  fs_avgfilesize;        /* expected average file size */
  337         int32_t  fs_avgfpdir;           /* expected # of files per directory */
  338         int32_t  fs_save_cgsize;        /* save real cg size to use fs_bsize */
  339         int32_t  fs_sparecon32[26];     /* reserved for future constants */
  340         int32_t  fs_flags;              /* see FS_ flags below */
  341         int32_t  fs_contigsumsize;      /* size of cluster summary array */ 
  342         int32_t  fs_maxsymlinklen;      /* max length of an internal symlink */
  343         int32_t  fs_old_inodefmt;       /* format of on-disk inodes */
  344         u_int64_t fs_maxfilesize;       /* maximum representable file size */
  345         int64_t  fs_qbmask;             /* ~fs_bmask for use with 64-bit size */
  346         int64_t  fs_qfmask;             /* ~fs_fmask for use with 64-bit size */
  347         int32_t  fs_state;              /* validate fs_clean field */
  348         int32_t  fs_old_postblformat;   /* format of positional layout tables */
  349         int32_t  fs_old_nrpos;          /* number of rotational positions */
  350         int32_t  fs_spare5[2];          /* old fs_postbloff */
  351                                         /* old fs_rotbloff */
  352         int32_t  fs_magic;              /* magic number */
  353 };
  354 
  355 /* Sanity checking. */
  356 #ifdef CTASSERT
  357 CTASSERT(sizeof(struct fs) == 1376);
  358 #endif
  359 
  360 /*
  361  * Filesystem identification
  362  */
  363 #define FS_UFS1_MAGIC   0x011954        /* UFS1 fast filesystem magic number */
  364 #define FS_UFS2_MAGIC   0x19540119      /* UFS2 fast filesystem magic number */
  365 #define FS_BAD_MAGIC    0x19960408      /* UFS incomplete newfs magic number */
  366 #define FS_OKAY         0x7c269d38      /* superblock checksum */
  367 #define FS_42INODEFMT   -1              /* 4.2BSD inode format */
  368 #define FS_44INODEFMT   2               /* 4.4BSD inode format */
  369 
  370 /*
  371  * Preference for optimization.
  372  */
  373 #define FS_OPTTIME      0       /* minimize allocation time */
  374 #define FS_OPTSPACE     1       /* minimize disk fragmentation */
  375 
  376 /*
  377  * Filesystem flags.
  378  *
  379  * The FS_UNCLEAN flag is set by the kernel when the filesystem was
  380  * mounted with fs_clean set to zero. The FS_DOSOFTDEP flag indicates
  381  * that the filesystem should be managed by the soft updates code.
  382  * Note that the FS_NEEDSFSCK flag is set and cleared only by the
  383  * fsck utility. It is set when background fsck finds an unexpected
  384  * inconsistency which requires a traditional foreground fsck to be
  385  * run. Such inconsistencies should only be found after an uncorrectable
  386  * disk error. A foreground fsck will clear the FS_NEEDSFSCK flag when
  387  * it has successfully cleaned up the filesystem. The kernel uses this
  388  * flag to enforce that inconsistent filesystems be mounted read-only.
  389  * The FS_INDEXDIRS flag when set indicates that the kernel maintains
  390  * on-disk auxiliary indexes (such as B-trees) for speeding directory
  391  * accesses. Kernels that do not support auxiliary indicies clear the
  392  * flag to indicate that the indicies need to be rebuilt (by fsck) before
  393  * they can be used.
  394  *
  395  * FS_ACLS indicates that ACLs are administratively enabled for the
  396  * file system, so they should be loaded from extended attributes,
  397  * observed for access control purposes, and be administered by object
  398  * owners.  FS_MULTILABEL indicates that the TrustedBSD MAC Framework
  399  * should attempt to back MAC labels into extended attributes on the
  400  * file system rather than maintain a single mount label for all
  401  * objects.
  402  */
  403 #define FS_UNCLEAN    0x01      /* filesystem not clean at mount */
  404 #define FS_DOSOFTDEP  0x02      /* filesystem using soft dependencies */
  405 #define FS_NEEDSFSCK  0x04      /* filesystem needs sync fsck before mount */
  406 #define FS_INDEXDIRS  0x08      /* kernel supports indexed directories */
  407 #define FS_ACLS       0x10      /* file system has ACLs enabled */
  408 #define FS_MULTILABEL 0x20      /* file system is MAC multi-label */
  409 #define FS_FLAGS_UPDATED 0x80   /* flags have been moved to new location */
  410 
  411 /*
  412  * Macros to access bits in the fs_active array.
  413  */
  414 #define ACTIVECGNUM(fs, cg)     ((fs)->fs_active[(cg) / (NBBY * sizeof(int))])
  415 #define ACTIVECGOFF(cg)         (1 << ((cg) % (NBBY * sizeof(int))))
  416 #define ACTIVESET(fs, cg)       do {                                    \
  417         if ((fs)->fs_active)                                            \
  418                 ACTIVECGNUM((fs), (cg)) |= ACTIVECGOFF((cg));           \
  419 } while (0)
  420 #define ACTIVECLEAR(fs, cg)     do {                                    \
  421         if ((fs)->fs_active)                                            \
  422                 ACTIVECGNUM((fs), (cg)) &= ~ACTIVECGOFF((cg));          \
  423 } while (0)
  424 
  425 /*
  426  * The size of a cylinder group is calculated by CGSIZE. The maximum size
  427  * is limited by the fact that cylinder groups are at most one block.
  428  * Its size is derived from the size of the maps maintained in the
  429  * cylinder group and the (struct cg) size.
  430  */
  431 #define CGSIZE(fs) \
  432     /* base cg */       (sizeof(struct cg) + sizeof(int32_t) + \
  433     /* old btotoff */   (fs)->fs_old_cpg * sizeof(int32_t) + \
  434     /* old boff */      (fs)->fs_old_cpg * sizeof(u_int16_t) + \
  435     /* inode map */     howmany((fs)->fs_ipg, NBBY) + \
  436     /* block map */     howmany((fs)->fs_fpg, NBBY) +\
  437     /* if present */    ((fs)->fs_contigsumsize <= 0 ? 0 : \
  438     /* cluster sum */   (fs)->fs_contigsumsize * sizeof(int32_t) + \
  439     /* cluster map */   howmany(fragstoblks(fs, (fs)->fs_fpg), NBBY)))
  440 
  441 /*
  442  * The minimal number of cylinder groups that should be created.
  443  */
  444 #define MINCYLGRPS      4
  445 
  446 /*
  447  * Convert cylinder group to base address of its global summary info.
  448  */
  449 #define fs_cs(fs, indx) fs_csp[indx]
  450 
  451 /*
  452  * Cylinder group block for a filesystem.
  453  */
  454 #define CG_MAGIC        0x090255
  455 struct cg {
  456         int32_t  cg_firstfield;         /* historic cyl groups linked list */
  457         int32_t  cg_magic;              /* magic number */
  458         int32_t  cg_old_time;           /* time last written */
  459         int32_t  cg_cgx;                /* we are the cgx'th cylinder group */
  460         int16_t  cg_old_ncyl;           /* number of cyl's this cg */
  461         int16_t  cg_old_niblk;          /* number of inode blocks this cg */
  462         int32_t  cg_ndblk;              /* number of data blocks this cg */
  463         struct  csum cg_cs;             /* cylinder summary information */
  464         int32_t  cg_rotor;              /* position of last used block */
  465         int32_t  cg_frotor;             /* position of last used frag */
  466         int32_t  cg_irotor;             /* position of last used inode */
  467         int32_t  cg_frsum[MAXFRAG];     /* counts of available frags */
  468         int32_t  cg_old_btotoff;        /* (int32) block totals per cylinder */
  469         int32_t  cg_old_boff;           /* (u_int16) free block positions */
  470         int32_t  cg_iusedoff;           /* (u_int8) used inode map */
  471         int32_t  cg_freeoff;            /* (u_int8) free block map */
  472         int32_t  cg_nextfreeoff;        /* (u_int8) next available space */
  473         int32_t  cg_clustersumoff;      /* (u_int32) counts of avail clusters */
  474         int32_t  cg_clusteroff;         /* (u_int8) free cluster map */
  475         int32_t  cg_nclusterblks;       /* number of clusters this cg */
  476         int32_t  cg_niblk;              /* number of inode blocks this cg */
  477         int32_t  cg_initediblk;         /* last initialized inode */
  478         int32_t  cg_sparecon32[3];      /* reserved for future use */
  479         ufs_time_t cg_time;             /* time last written */
  480         int64_t  cg_sparecon64[3];      /* reserved for future use */
  481         u_int8_t cg_space[1];           /* space for cylinder group maps */
  482 /* actually longer */
  483 };
  484 
  485 /*
  486  * Macros for access to cylinder group array structures
  487  */
  488 #define cg_chkmagic(cgp) ((cgp)->cg_magic == CG_MAGIC)
  489 #define cg_inosused(cgp) \
  490     ((u_int8_t *)((u_int8_t *)(cgp) + (cgp)->cg_iusedoff))
  491 #define cg_blksfree(cgp) \
  492     ((u_int8_t *)((u_int8_t *)(cgp) + (cgp)->cg_freeoff))
  493 #define cg_clustersfree(cgp) \
  494     ((u_int8_t *)((u_int8_t *)(cgp) + (cgp)->cg_clusteroff))
  495 #define cg_clustersum(cgp) \
  496     ((int32_t *)((uintptr_t)(cgp) + (cgp)->cg_clustersumoff))
  497 
  498 /*
  499  * Turn filesystem block numbers into disk block addresses.
  500  * This maps filesystem blocks to device size blocks.
  501  */
  502 #define fsbtodb(fs, b)  ((daddr_t)(b) << (fs)->fs_fsbtodb)
  503 #define dbtofsb(fs, b)  ((b) >> (fs)->fs_fsbtodb)
  504 
  505 /*
  506  * Cylinder group macros to locate things in cylinder groups.
  507  * They calc filesystem addresses of cylinder group data structures.
  508  */
  509 #define cgbase(fs, c)   (((ufs2_daddr_t)(fs)->fs_fpg) * (c))
  510 #define cgdmin(fs, c)   (cgstart(fs, c) + (fs)->fs_dblkno)      /* 1st data */
  511 #define cgimin(fs, c)   (cgstart(fs, c) + (fs)->fs_iblkno)      /* inode blk */
  512 #define cgsblock(fs, c) (cgstart(fs, c) + (fs)->fs_sblkno)      /* super blk */
  513 #define cgtod(fs, c)    (cgstart(fs, c) + (fs)->fs_cblkno)      /* cg block */
  514 #define cgstart(fs, c)                                                  \
  515        ((fs)->fs_magic == FS_UFS2_MAGIC ? cgbase(fs, c) :               \
  516        (cgbase(fs, c) + (fs)->fs_old_cgoffset * ((c) & ~((fs)->fs_old_cgmask))))
  517 
  518 /*
  519  * Macros for handling inode numbers:
  520  *     inode number to filesystem block offset.
  521  *     inode number to cylinder group number.
  522  *     inode number to filesystem block address.
  523  */
  524 #define ino_to_cg(fs, x)        ((x) / (fs)->fs_ipg)
  525 #define ino_to_fsba(fs, x)                                              \
  526         ((ufs2_daddr_t)(cgimin(fs, ino_to_cg(fs, x)) +                  \
  527             (blkstofrags((fs), (((x) % (fs)->fs_ipg) / INOPB(fs))))))
  528 #define ino_to_fsbo(fs, x)      ((x) % INOPB(fs))
  529 
  530 /*
  531  * Give cylinder group number for a filesystem block.
  532  * Give cylinder group block number for a filesystem block.
  533  */
  534 #define dtog(fs, d)     ((d) / (fs)->fs_fpg)
  535 #define dtogd(fs, d)    ((d) % (fs)->fs_fpg)
  536 
  537 /*
  538  * Extract the bits for a block from a map.
  539  * Compute the cylinder and rotational position of a cyl block addr.
  540  */
  541 #define blkmap(fs, map, loc) \
  542     (((map)[(loc) / NBBY] >> ((loc) % NBBY)) & (0xff >> (NBBY - (fs)->fs_frag)))
  543 
  544 /*
  545  * The following macros optimize certain frequently calculated
  546  * quantities by using shifts and masks in place of divisions
  547  * modulos and multiplications.
  548  */
  549 #define blkoff(fs, loc)         /* calculates (loc % fs->fs_bsize) */ \
  550         ((loc) & (fs)->fs_qbmask)
  551 #define fragoff(fs, loc)        /* calculates (loc % fs->fs_fsize) */ \
  552         ((loc) & (fs)->fs_qfmask)
  553 #define lfragtosize(fs, frag)   /* calculates ((off_t)frag * fs->fs_fsize) */ \
  554         (((off_t)(frag)) << (fs)->fs_fshift)
  555 #define lblktosize(fs, blk)     /* calculates ((off_t)blk * fs->fs_bsize) */ \
  556         (((off_t)(blk)) << (fs)->fs_bshift)
  557 /* Use this only when `blk' is known to be small, e.g., < NDADDR. */
  558 #define smalllblktosize(fs, blk)    /* calculates (blk * fs->fs_bsize) */ \
  559         ((blk) << (fs)->fs_bshift)
  560 #define lblkno(fs, loc)         /* calculates (loc / fs->fs_bsize) */ \
  561         ((loc) >> (fs)->fs_bshift)
  562 #define numfrags(fs, loc)       /* calculates (loc / fs->fs_fsize) */ \
  563         ((loc) >> (fs)->fs_fshift)
  564 #define blkroundup(fs, size)    /* calculates roundup(size, fs->fs_bsize) */ \
  565         (((size) + (fs)->fs_qbmask) & (fs)->fs_bmask)
  566 #define fragroundup(fs, size)   /* calculates roundup(size, fs->fs_fsize) */ \
  567         (((size) + (fs)->fs_qfmask) & (fs)->fs_fmask)
  568 #define fragstoblks(fs, frags)  /* calculates (frags / fs->fs_frag) */ \
  569         ((frags) >> (fs)->fs_fragshift)
  570 #define blkstofrags(fs, blks)   /* calculates (blks * fs->fs_frag) */ \
  571         ((blks) << (fs)->fs_fragshift)
  572 #define fragnum(fs, fsb)        /* calculates (fsb % fs->fs_frag) */ \
  573         ((fsb) & ((fs)->fs_frag - 1))
  574 #define blknum(fs, fsb)         /* calculates rounddown(fsb, fs->fs_frag) */ \
  575         ((fsb) &~ ((fs)->fs_frag - 1))
  576 
  577 /*
  578  * Determine the number of available frags given a
  579  * percentage to hold in reserve.
  580  */
  581 #define freespace(fs, percentreserved) \
  582         (blkstofrags((fs), (fs)->fs_cstotal.cs_nbfree) + \
  583         (fs)->fs_cstotal.cs_nffree - \
  584         (((off_t)((fs)->fs_dsize)) * (percentreserved) / 100))
  585 
  586 /*
  587  * Determining the size of a file block in the filesystem.
  588  */
  589 #define blksize(fs, ip, lbn) \
  590         (((lbn) >= NDADDR || (ip)->i_size >= smalllblktosize(fs, (lbn) + 1)) \
  591             ? (fs)->fs_bsize \
  592             : (fragroundup(fs, blkoff(fs, (ip)->i_size))))
  593 #define sblksize(fs, size, lbn) \
  594         (((lbn) >= NDADDR || (size) >= ((lbn) + 1) << (fs)->fs_bshift) \
  595           ? (fs)->fs_bsize \
  596           : (fragroundup(fs, blkoff(fs, (size)))))
  597 
  598 
  599 /*
  600  * Number of inodes in a secondary storage block/fragment.
  601  */
  602 #define INOPB(fs)       ((fs)->fs_inopb)
  603 #define INOPF(fs)       ((fs)->fs_inopb >> (fs)->fs_fragshift)
  604 
  605 /*
  606  * Number of indirects in a filesystem block.
  607  */
  608 #define NINDIR(fs)      ((fs)->fs_nindir)
  609 
  610 extern int inside[], around[];
  611 extern u_char *fragtbl[];
  612 
  613 #endif



        ;; From /usr/include/linux/fs.h
        %define SEEK_SET        0  ; seek relative to beginning of file
        %define SEEK_CUR        1  ; seek relative to current file position
        %define SEEK_END        2  ; seek relative to end of file
        %define SEEK_MAX  SEEK_END
        %define MAY_EXEC        1
        %define MAY_WRITE       2
        %define MAY_READ        4
        %define MAY_APPEND      8
        %define MAY_ACCESS      16
        %define MAY_OPEN        32
        %define MAY_CHDIR       64
        ;; From /usr/include/bits/fcntl.h
        %define O_ACCMODE       0003
        %define O_RDONLY        00
        %define O_WRONLY        01
        %define O_RDWR          02
        %define O_CREAT         0100  ; not fcntl
        %define O_EXCL          0200  ; not fcntl
        %define O_NOCTTY        0400  ; not fcntl
        %define O_TRUNC         01000 ; not fcntl
        %define O_APPEND        02000
        %define O_NONBLOCK      04000
        %define O_NDELAY        O_NONBLOCK
        %define O_SYNC          04010000
        %define O_FSYNC         O_SYNC
        %define O_ASYNC         020000
        %define O_DIRECTORY     0200000  ; Must be a directory.
        %define O_NOFOLLOW      0400000  ; Do not follow links.
        %define O_CLOEXEC       02000000 ; Set close_on_exec.
        %define O_DIRECT        040000   ; Direct disk access.
        %define O_NOATIME       01000000 ; Do not set atime.

        ;; For now Linux has synchronisity options for data and read operations.
        ;; We define the symbols here but let them do the same as O_SYNC since
        ;; this is a superset.
        %define O_DSYNC         010000 ; Synchronize data.
        %define O_RSYNC         O_SYNC ; Synchronize read operations.

        %define O_LARGEFILE     0
        %define O_LARGEFILE     0100000

        ;; Values for the second argument to `fcntl'.
        %define F_DUPFD         0 ; Duplicate file descriptor.
        %define F_GETFD         1 ; Get file descriptor flags.
        %define F_SETFD         2 ; Set file descriptor flags.
        %define F_GETFL         3 ; Get file status flags.
        %define F_SETFL         4 ; Set file status flags.

        ;; Other
        %define STD_IN          0
        %define STD_OUT         1
        %define STD_ERR         2
