# why-slow — Proposed & Researched Rules Backlog

This document catalogs prospective diagnostic rules researched for future implementation in `why-slow`. All proposed rules follow the strict zero-privilege, zero-dependency, and multi-signal safety invariants.

---

## 📌 Phase 1 Backlog: Implemented (8 Rules)
* `BASE_FS_READONLY_REMOUNT` (Tier 1 — Critical)
* `CONT_UDP_BUFFER_OVERRUN` (Tier 2 — High)
* `CONT_TCP_LISTEN_OVERFLOW_STALL` (Tier 2 — High)
* `CONT_HUGETLB_POOL_EXHAUSTION` (Tier 2 — High)
* `CONT_PTRACE_TRACER_ATTACH` (Tier 2 — High)
* `EDGE_KCOMPACTD_CPU_SPIN` (Tier 3 — Medium)
* `EDGE_MIN_FREE_KBYTES_STALL` (Tier 3 — Medium)
* `EDGE_CORE_PATTERN_PIPE_STALL` (Tier 3 — Medium)

---

## 📌 Phase 2 Backlog: Implemented (8 Rules)
* `CONT_DM_QUEUE_CONGESTION` (Tier 2 — High)
* `CONT_SYSV_SEMAPHORE_LIMIT` (Tier 2 — High)
* `EDGE_TCP_PAWS_DROP` (Tier 3 — Medium)
* `EDGE_NET_IFACE_CARRIER_FLAP` (Tier 3 — Medium)
* `EDGE_LOOP_DEVICE_SERIALIZATION` (Tier 3 — Medium)
* `EDGE_CMA_ZONE_EXHAUSTION` (Tier 3 — Medium)
* `EDGE_RT_SCHED_THROTTLING` (Tier 3 — Medium)
* `EDGE_SCHED_MIGRATION_BOUNCE` (Tier 3 — Medium)

---

## 📌 Phase 3 Backlog: Implemented (8 Rules — Rules Catalog at 98 Rules)
* `CONT_AIO_EVENT_LIMIT_SATURATION` (Tier 2 — High)
* `CONT_KSWAPD_CPU_SPIN` (Tier 2 — High)
* `CONT_MD_RAID_RESYNC_STALL` (Tier 2 — High)
* `CONT_NET_OUT_OF_ORDER_STALL` (Tier 2 — High)
* `CONT_POSIX_RTSIG_QUEUE_SATURATION` (Tier 2 — High)
* `EDGE_IP_FRAG_REASM_DROPS` (Tier 3 — Medium)
* `EDGE_CGROUP_V2_FREEZE_HANG` (Tier 3 — Medium)
* `EDGE_SYSV_SHM_SEGMENT_LIMIT` (Tier 3 — Medium)

---

## 📌 Phase 4 Backlog: Implemented (8 Rules — Rules Catalog at 106 Rules)
* `CONT_UDP_SNDBUF_EXHAUSTION` (Tier 2 — High)
* `CONT_CGROUP_V1_CPU_SHARES_STARVATION` (Tier 2 — High)
* `CONT_HUGEPAGE_LEAK_NO_REUSE` (Tier 2 — High)
* `CONT_NET_TCP_ABORT_ON_CLOSE` (Tier 2 — High)
* `CONT_SCHED_YIELD_SPIN_CHURN` (Tier 2 — High)
* `EDGE_NET_DEV_RX_NO_BUFFERS` (Tier 3 — Medium)
* `EDGE_TRANSPARENT_HUGEPAGE_DEFRAG_ALWAYS` (Tier 3 — Medium)
* `EDGE_CGROUP_MEMORY_MAX_OOM_STALL` (Tier 3 — Medium)

---

## 📌 Phase 5 Backlog: Implemented (8 Rules — Rules Catalog at 114 Rules)
* `CONT_NET_TCP_COLLAPSE_PRUNE` (Tier 2 — High)
* `CONT_NET_TCP_MEMORY_ALLOC_FAIL` (Tier 2 — High)
* `CONT_NET_TCP_ZERO_WINDOW_DROP` (Tier 2 — High)
* `CONT_FUTEX_PI_DEADLOCK_STALL` (Tier 2 — High)
* `CONT_NET_ARP_TABLE_TRASH` (Tier 2 — High)
* `EDGE_THP_SCAN_EXHAUSTION_STALL` (Tier 3 — Medium)
* `EDGE_NET_DEV_TX_QUEUE_TIMEOUT` (Tier 3 — Medium)
* `EDGE_CGROUP_CPU_CORE_PIN_STARVATION` (Tier 3 — Medium)

---

## 📌 Phase 6 Backlog: Implemented (8 Rules — Rules Catalog at 122 Rules)
* `CONT_DIRTY_PAGES_DIRECT_SYNC_STALL` (Tier 2 — High)
* `CONT_NFS_RPC_SLOT_TABLE_SATURATION` (Tier 2 — High)
* `CONT_UNIX_SOCKET_BACKLOG_OVERFLOW` (Tier 2 — High)
* `CONT_VFS_INODE_LOCK_CONTENTION` (Tier 2 — High)
* `CONT_KERNEL_LOCKD_BLOCKED` (Tier 2 — High)
* `EDGE_HUGETLB_VMA_MISALIGN_FAULT` (Tier 3 — Medium)
* `EDGE_TCP_CHRONIC_RTO_COLLAPSE` (Tier 3 — Medium)
* `EDGE_MEMCG_SOCK_MEMORY_THROTTLE` (Tier 3 — Medium)

---

## 📌 Phase 7 Backlog: Implemented (8 Rules — Rules Catalog at 130 Rules)
* `CONT_SCHED_AUTOGROUP_STARVATION` (Tier 2 — High)
* `CONT_FTRACE_RING_BUFFER_STALL` (Tier 2 — High)
* `CONT_NET_DEV_GRO_CELL_DROP` (Tier 2 — High)
* `CONT_MEM_COMPACT_MIGRATION_FAIL_RATE` (Tier 2 — High)
* `EDGE_TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_SPIN` (Tier 3 — Medium)
* `EDGE_SYSFS_CPU_HOTPLUG_LOCK_CONTENTION` (Tier 3 — Medium)
* `EDGE_NET_IP_MULTICAST_IGMP_REPORT_STALL` (Tier 3 — Medium)
* `EDGE_PROC_PID_TASK_PTHREAD_LIMIT` (Tier 3 — Medium)


