/*
 * WriteBuffer.h
 * Copyright(C) 2012 Drobo Inc. All rights reserved
 */

typedef unsigned long long U64;
typedef unsigned long  U32;
typedef unsigned short U16;
typedef unsigned char  U8;
typedef unsigned long long uint64;
typedef unsigned long  uint32;
typedef unsigned short uint16;
typedef unsigned char  uint8;

typedef int  BOOL;
typedef unsigned long long TD_ATOMIC64;
typedef long STATUS;
typedef unsigned long TD_ATOMIC32;
#define TRUE (1)
#define FALSE (0)

#define WRITE_JOURNAL_RESCAN_PERF 0
#define TRACK_WRITE_BUFFER_ALLOC_RELEASE 1

#undef ISCSI_TGT_WRITE_BUFFER_DEBUG

#define WRITE_BUFFER_MARK_FREED_BUFFERS 0

#if WRITE_BUFFER_MARK_FREED_BUFFERS
#define WRITE_JOURNAL_FREED_BUFFER_BEGIN_MAGIC_MARKER 0xBEEF0000
#define WRITE_JOURNAL_FREED_BUFFER_END_MAGIC_MARKER 0xDEAD0000
#define WRITE_JOURNAL_ALLOCATED_BUFFER_BEGIN_MAGIC_MARKER 0xCAFE0000
#define WRITE_JOURNAL_ALLOCATED_BUFFER_END_MAGIC_MARKER 0xFACE0000
#endif

#define WRITE_JOURNAL_WAIT_TIME_1X_INDEX 0
#define WRITE_JOURNAL_WAIT_TIME_2X_INDEX 1
#define WRITE_JOURNAL_WAIT_TIMES_NUM     2

// Shared Memory Allocation.
// Make sure these allocations plus buffer descriptors fit in the write journal partition.
#define TRANS_WRITE_BUFFER_SIZE (16 * 1024)
#define BULK_WRITE_BUFFER_SIZE  (256 * 1024)
#define TRANS_THRESHOLD (TRANS_WRITE_BUFFER_SIZE * 2)
/*
#if PLATFORM == GORT
#define MAX_TRANS_WRITE_BUFFER 2048
#define MAX_BULK_WRITE_BUFFER  1800
#else 
#define MAX_TRANS_WRITE_BUFFER 512
#define MAX_BULK_WRITE_BUFFER  223
#endif
*/
#define SHARED_PARTITION_INFO_AREA_SIZE 512
#define WRITE_JOURNAL_DESCRIPTOR_MARKER 0xFEED0000

#define WRITE_BUFFER_FREE 1
#define WRITE_BUFFER_IN_USE 0

#define ATOMIC_SET32 iscsiTgtAtomicSet32
#define ATOMIC_SET64 iscsiTgtAtomicSet64
#define ATOMIC_GET32 iscsiTgtAtomicGet32
#define ATOMIC_GET64 iscsiTgtAtomicGet64

#define ATOMIC_INC32(x) iscsiTgtAtomicAdd32(x, 1)
#define ATOMIC_INC64(x) iscsiTgtAtomicAdd64(x, 1)
#define ATOMIC_DEC32(x) iscsiTgtAtomicSub32(x, 1)
#define ATOMIC_DEC64(x) iscsiTgtAtomicSub64(x, 1)

#define ATOMIC_INC_RETURN32(x) iscsiTgtAtomicAddReturn32(x, 1)
#define ATOMIC_INC_RETURN64(x) iscsiTgtAtomicAddReturn64(x, 1)
#define ATOMIC_DEC_RETURN32(x) iscsiTgtAtomicSubReturn32(x, 1)
#define ATOMIC_DEC_RETURN64(x) iscsiTgtAtomicSubReturn64(x, 1)

#define DROBO_ARM 1 
#ifdef DROBO_ARM
#define SYNC 
#define CPU_FAMILY DROBO_ARM
#else
#define SYNC __asm__ __volatile__ ("sync" : : :"memory")
#endif

inline void iscsiTgtAtomicSet32(TD_ATOMIC32 *var, U32 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var = val;
#else
  U32 temp;
  __asm__ __volatile__ (
      "1:    ll    %0, %1;      \n"
      "      sc    %2, %1;      \n"
      "      beqz  %0, 1b;      \n"
      : "=&r"(temp), "=m"(*var)
      : "r"(val), "m"(*var)
      :);
#endif
}

inline void iscsiTgtAtomicSet64(TD_ATOMIC64 *var, U64 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var = val;
#else
  U64 temp;
  __asm__ __volatile__ (
      "1:    lld   %0, %1;      \n"
      "      scd   %2, %1;      \n"
      "      beqz  %0, 1b;      \n"
      : "=&r"(temp), "=m"(*var)
      : "r"(val), "m"(*var)
      :);
#endif
}

inline U32 iscsiTgtAtomicGet32(TD_ATOMIC32 *var)
{
  return *var;
}

inline U64 iscsiTgtAtomicGet64(TD_ATOMIC64 *var)
{
  return *var;
}

inline void iscsiTgtAtomicAdd32(TD_ATOMIC32 *var, U32 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var += val;
#else
  U32 temp;

  __asm__ __volatile__(
    "1:   ll      %0, %1      # atomic_add\n"
    "     addu    %0, %2                  \n"
    "     sc      %0, %1                  \n"
    "     beqz    %0, 1b                  \n"
    : "=&r" (temp), "=m" (*var)
    : "Ir" (val), "m" (*var));
#endif
}

inline void iscsiTgtAtomicAdd64(TD_ATOMIC64 *var, U64 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var += val;
#else
  U64 temp;

  __asm__ __volatile__(
    "1:   lld     %0, %1      # atomic_add\n"
    "     daddu   %0, %2                  \n"
    "     scd     %0, %1                  \n"
    "     beqz    %0, 1b                  \n"
    : "=&r" (temp), "=m" (*var)
    : "Ir" (val), "m" (*var));
#endif
}

inline void iscsiTgtAtomicSub32(TD_ATOMIC32 *var, U32 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var -= val;
#else 
  U32 temp;

  __asm__ __volatile__(
    "1:   ll      %0, %1      # atomic_sub\n"
    "     subu    %0, %2                  \n"
    "     sc      %0, %1                  \n"
    "     beqz    %0, 1b                  \n"
    : "=&r" (temp), "=m" (*var)
    : "Ir" (val), "m" (*var));
#endif
}

inline void iscsiTgtAtomicSub64(TD_ATOMIC64 *var, U64 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var -= val;
#else
  U64 temp;

  __asm__ __volatile__(
    "1:   lld     %0, %1      # atomic_sub\n"
    "     dsubu   %0, %2                  \n"
    "     scd     %0, %1                  \n"
    "     beqz    %0, 1b                  \n"
    : "=&r" (temp), "=m" (*var)
    : "Ir" (val), "m" (*var));
#endif
}

inline U32 iscsiTgtAtomicAddReturn32(TD_ATOMIC32 *var, U32 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var += val;
  return *var;
#else 
  U32 temp, result;

  __asm__ __volatile__(
    ".set push               # atomic_add_return\n"
    ".set noreorder                             \n"
    "1:   ll      %1, %2                        \n"
    "     addu    %0, %1, %3                    \n"
    "     sc      %0, %2                        \n"
    "     beqz    %0, 1b                        \n"
    "     addu    %0, %1, %3                    \n"
    ".set pop                                   \n"
    : "=&r" (result), "=&r" (temp), "=m" (*var)
    : "Ir" (val), "m" (*var)
    : "memory");

  return result;
#endif
}

inline U64 iscsiTgtAtomicAddReturn64(TD_ATOMIC64 *var, U64 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var += val;
  return *var;
#else 
  U64 temp, result;

  __asm__ __volatile__(
    ".set push               # atomic_add_return\n"
    ".set noreorder                             \n"
    "1:   lld     %1, %2                        \n"
    "     daddu   %0, %1, %3                    \n"
    "     scd     %0, %2                        \n"
    "     beqz    %0, 1b                        \n"
    "     daddu   %0, %1, %3                    \n"
    ".set pop                                   \n"
    : "=&r" (result), "=&r" (temp), "=m" (*var)
    : "Ir" (val), "m" (*var)
    : "memory");

  return result;
#endif
}

inline U32 iscsiTgtAtomicSubReturn32(TD_ATOMIC32 *var, U32 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var -= val;
  return *var;
#else 
  U32 temp, result;

    __asm__ __volatile__(
      ".set push                                   \n"
      ".set noreorder           # atomic_sub_return\n"
      "1:   ll    %1, %2                           \n"
      "     subu  %0, %1, %3                       \n"
      "     sc    %0, %2                           \n"
      "     beqz  %0, 1b                           \n"
      "     subu  %0, %1, %3                       \n"
      ".set pop                                    \n"
      : "=&r" (result), "=&r" (temp), "=m" (*var)
      : "Ir" (val), "m" (*var)
      : "memory");

    return result;
#endif
}

inline U64 iscsiTgtAtomicSubReturn64(TD_ATOMIC64 *var, U64 val)
{
#if (CPU_FAMILY == DROBO_ARM)
  *var -= val;
  return *var;
#else 
  U64 temp, result;

    __asm__ __volatile__(
      ".set push                                   \n"
      ".set noreorder           # atomic_sub_return\n"
      "1:   lld   %1, %2                           \n"
      "     dsubu %0, %1, %3                       \n"
      "     scd   %0, %2                           \n"
      "     beqz  %0, 1b                           \n"
      "     dsubu %0, %1, %3                       \n"
      ".set pop                                    \n"
      : "=&r" (result), "=&r" (temp), "=m" (*var)
      : "Ir" (val), "m" (*var)
      : "memory");

    return result;
#endif
}

enum WriteBufferType
{
    Bulk = 1,
    Trans = 2
};

// Try to keep this cacheline aligned
typedef struct WriteBufferDescriptor 
{
  // This is set by the consumer and cleared by the allocator.
  // 1 means buffer can be reclaimed by the allocator.
  U32 releasedToAllocator;
  
  // The signature is WRITE_JOURNAL_DESCRIPTOR_MARKER
  // plus the index of this descriptor in the pool
  U32 signature;
  
  // Pointers below are only valid on the Lx (allocator) cores
  struct WriteBufferDescriptor *next;  // pointer to the next descriptor on free list
  struct WriteBufferDescriptor *prev;  // pointer to the previous descriptor on free list
  struct WriteBufferDescriptor *buddy; // pointer to double-buffer buddy if there is one
  U8  *writeBuffer;
  // Allows us to correlate the buffer to the cmd and session, purely for diagnostic purposes.
  U32 pCmd;
  U32 initTaskTag;
  U32 intercoreTag;
  U32 pConnection;
  U32 stateFlags; // Track where in the system the buffer is
  U32 free_intent_time;   // When we start to free this obj
  U32 alloc_dealloc_time; // When it was touched.
  U32 cmdFlags;           // Command flags ...
  U32 iscsiCmd;           // The iSCSI cmd that caused this
  U32 scsiCmd;            // And the scsiCmd ...

  // Delay for the response to the corresponding command.
  // This field is shared by Vx and Lx.
  U32 pacingDelay;
  
  U8 reserveForVx[20];
  
  U64 allocGenNumber;
  U64 rescanGenNumber;
  U32 rescanThread;
  U32 allocThread;
  
  // Padding out to cacheline size of 128 bytes.
  U8 padding[16];
} __packed WriteBufferDescriptor;

typedef struct BufferDescListLocked {
  WriteBufferDescriptor *ListHead;
  /*PREEMPTION_LOCK_OBJ ListSem;*/  // Semaphore for this list
  U32 NumElements;             // Number of elements in the list
}BufferDescListLocked;

// Allocator private info does not need to be in shared memory.
// These are things used only on a live system and not across reboots.

typedef struct PoolAllocatorPrivateInfo{
  BufferDescListLocked FreeListSingle;
  BufferDescListLocked FreeListDouble;
  U32  noFreeSingle;
  U32  noFreeDouble;
  U64 allocReleaseGenNumber;
} __packed PoolAllocatorPrivateInfo;


typedef struct WriteBufferPoolInfo{
  U32 BufferStartOffset;  // Offset of the first buffer
  U32 BufferEndOffset;    // End of Write Buffer Pool
  U32 DescStartOffset;    // Start of the descriptor section
  U32 DescEndOffset;      // End of the descriptor section
  enum WriteBufferType Type;
  U32 NumBuffers;
  U32 BufferSize;         // Buffer size in bytes
  U64 miss_counter_single; 
  U64 miss_counter_double; 
  U64 hit_counter_single; 
  U64 hit_counter_double;
  struct PoolAllocatorPrivateInfo *LxPrivate;
  void *VxPrivate;
} __packed WriteBufferPoolInfo;

// Make sure this fits within SHARED_PARTITION_INFO_AREA_SIZE
typedef struct SharedPartitionInfoStruct
{ 
  /* Fields common to all cores */
  U32 SharedPartitionSize;
  U32 SharedPartitionDataRegionSize;
  U32 SharedPartitionBufferRegionSize;
  WriteBufferPoolInfo TransPoolInfo;  // Buffer pool for transactional data
  WriteBufferPoolInfo BulkPoolInfo;   // Buffer pool for bulk data
  
  U8 *LxSharedPartitionDataStart; // Only valid on the Lx core
  U8 *VxSharedPartitionDataStart; // Only valid on the Vx core
} __packed SharedPartitionInfoStruct;

/*
typedef struct iscsiTgtWriteBufferInfo
{
  SharedPartitionInfoStruct *SharedPartitionInfo;
  PREEMPTION_LOCK_OBJ SharedPartitionSemaphore;
  BOOL forceWakeup;
  U32 numWaitTimes[WRITE_JOURNAL_WAIT_TIMES_NUM];
} iscsiTgtWriteBufferInfo;
*/

void scsiTgtWriteBufferInit(void * buffer, U32 size);
void *scsiTgtWriteBufferAllocate(U32 numberBytes);
void scsiTgtWriteBufferSetTag(void * buffer, U32 tag);
void scsiTgtWriteBufferSetState(void * buffer, U32 state);
void scsiTgtWriteBufferSetFlags(void * buffer, U32 flags);
void scsiTgtWriteBufferSetCmd(void * buffer, U32 cmd);
void scsiTgtWriteBufferAndFlags(void * buffer, U32 flags);
void scsiTgtWriteBufferSetScsiCmd(void * buffer, U32 cmd);
U32 scsiTgtWriteBufferFreeBuffer(void * inBuffer, U32 numberBytes); // returns the intercoreTag
U32 scsiTgtWriteBufferRescanBuffers(U32 numberBytes);
bool scsiTgtIsWriteBuffer(void *buffer);
U32 scsiTgtWriteBufferGetDelay(void * buffer);
int rescanJ1CommandHandler(void);
void scsiTgtWriteBufferSetup(void *buffer);

