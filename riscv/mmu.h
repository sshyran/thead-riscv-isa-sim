// See LICENSE for license details.

#ifndef _RISCV_MMU_H
#define _RISCV_MMU_H

#include "decode.h"
#include "trap.h"
#include "common.h"
#include "config.h"
#include "simif.h"
#include "processor.h"
#include "memtracer.h"
#include "byteorder.h"
#include <stdlib.h>
#include <vector>
#include "Force_Memory.h"

//!< MmuEvent - struct used to record memory events from simulator...
typedef enum _Memtype { Strong,Device,Normal } Memtype;
typedef unsigned int CacheType;
typedef unsigned int CacheAttrs;
struct MmuEvent
{
  MmuEvent(uint64_t _va, uint64_t _pa, Memtype _type, bool _has_stage_two, CacheType _outer_type, CacheAttrs _outer_attrs, CacheType _inner_type, CacheAttrs _inner_attrs)
    : va(_va), pa(_pa), type(_type), has_stage_two(_has_stage_two), outer_type(_outer_type), outer_attrs(_outer_attrs), inner_type(_inner_type), inner_attrs(_inner_attrs)
  {
  }

  uint64_t va;
  uint64_t pa;
  Memtype type;
  bool has_stage_two;
  CacheType outer_type;
  CacheAttrs outer_attrs;
  CacheType inner_type;
  CacheAttrs inner_attrs;
};

struct SimException {
  SimException() : mExceptionID(0), mExceptionAttributes(0), mpComments(""), mEPC(0) {}
  SimException(uint32_t exceptionID, uint32_t exceptionAttributes, const char* comments, uint64_t epc) :
    mExceptionID(exceptionID), mExceptionAttributes(exceptionAttributes), mpComments(comments), mEPC(epc) {}
  uint32_t mExceptionID; //!< 0x4E: eret. Other values are scause or mcause codes.   
  uint32_t  mExceptionAttributes;  //!< copied from tval. 
  const char* mpComments; //!<  exception comments, identifies enter, exit and m or s modes.
  uint64_t mEPC; //!< exception program counter.
};

extern "C" {
    // memory r/w callback
    void update_generator_memory(uint32_t cpuid, uint64_t virtualAddress, uint32_t memBank, uint64_t physicalAddress, uint32_t size, const char *pBytes, const char *pAccessType);

    // mmu update callback
    void update_mmu_event(MmuEvent *event);

    //exception handling callback
    void update_exception_event(const SimException* exception);
}

// virtual memory configuration
#define PGSHIFT 12
const reg_t PGSIZE = 1 << PGSHIFT;
const reg_t PGMASK = ~(PGSIZE-1);
#define MAX_PADDR_BITS 56 // imposed by Sv39 / Sv48

struct insn_fetch_t
{
  insn_func_t func;
  insn_t insn;
};

struct icache_entry_t {
  reg_t tag;
  struct icache_entry_t* next;
  insn_fetch_t data;
};

struct tlb_entry_t {
  char* host_offset;
  reg_t target_offset;
};

class trigger_matched_t
{
  public:
    trigger_matched_t(int index,
        trigger_operation_t operation, reg_t address, reg_t data) :
      index(index), operation(operation), address(address), data(data) {}

    int index;
    trigger_operation_t operation;
    reg_t address;
    reg_t data;
};

// this class implements a processor's port into the virtual memory system.
// an MMU and instruction cache are maintained for simulator performance.
class mmu_t
{
private:
  std::map<reg_t, reg_t> alloc_cache;
  std::vector<std::pair<reg_t, reg_t >> addr_tbl;
public:
  mmu_t(simif_t* sim, processor_t* proc);
  ~mmu_t();

#define RISCV_XLATE_VIRT (1U << 0)
#define RISCV_XLATE_VIRT_HLVX (1U << 1)

  inline reg_t misaligned_load(reg_t addr, size_t size, uint32_t xlate_flags)
  {
#ifdef RISCV_ENABLE_MISALIGNED
    reg_t res = 0;
    for (size_t i = 0; i < size; i++)
      res += (reg_t)load_uint8(addr + (target_big_endian? size-1-i : i)) << (i * 8);
    return res;
#else
    bool gva = ((proc) ? proc->state.v : false) || (RISCV_XLATE_VIRT & xlate_flags);
    throw trap_load_address_misaligned(gva, addr, 0, 0);
#endif
  }

  inline reg_t misaligned_load_partially_initialized(reg_t addr, size_t size, uint32_t xlate_flags)
  {
#ifdef RISCV_ENABLE_MISALIGNED
    reg_t res = 0;
    for (size_t i = 0; i < size; i++)
      res += (reg_t)load_partially_initialized_uint8(addr + i) << (i * 8);
    return res;
#else
    bool gva = ((proc) ? proc->state.v : false) || (RISCV_XLATE_VIRT & xlate_flags);
    throw trap_load_address_misaligned(gva, addr, 0, 0);
#endif
  }

  inline void misaligned_store(reg_t addr, reg_t data, size_t size, uint32_t xlate_flags)
  {
#ifdef RISCV_ENABLE_MISALIGNED
    for (size_t i = 0; i < size; i++)
      store_uint8(addr + (target_big_endian? size-1-i : i), data >> (i * 8));
#else
    bool gva = ((proc) ? proc->state.v : false) || (RISCV_XLATE_VIRT & xlate_flags);
    throw trap_store_address_misaligned(gva, addr, 0, 0);
#endif
  }

#ifndef RISCV_ENABLE_COMMITLOG
# define READ_MEM(addr, size) ({})
#else
# define READ_MEM(addr, size) \
  proc->state.log_mem_read.push_back(std::make_tuple(addr, 0, size));
#endif

  // template for functions that load an aligned value from memory
  #define load_func(type, prefix, xlate_flags) \
    inline type##_t prefix##_##type(reg_t addr, bool require_alignment = false) { \
      if (unlikely(addr & (sizeof(type##_t)-1))) { \
        if (require_alignment) load_reserved_address_misaligned(addr); \
        else return misaligned_load(addr, sizeof(type##_t), xlate_flags); \
      } \
      reg_t vpn = addr >> PGSHIFT; \
      size_t size = sizeof(type##_t); \
      if ((xlate_flags) == 0 && likely(tlb_load_tag[vpn % TLB_ENTRIES] == vpn)) { \
        reg_t paddr = tlb_data[vpn % TLB_ENTRIES].target_offset + addr; \
        type##_t data = static_cast<type##_t>(sim->sparse_read(paddr, size)); \
        data = to_value_from_be(data); \
        type##_t update_data = to_target_from_value(data); \
        update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, size, reinterpret_cast<const char*>(&update_data), "read"); \
        return data; \
      } \
      if ((xlate_flags) == 0 && unlikely(tlb_load_tag[vpn % TLB_ENTRIES] == (vpn | TLB_CHECK_TRIGGERS))) { \
        reg_t paddr = tlb_data[vpn % TLB_ENTRIES].target_offset + addr; \
        type##_t data = static_cast<type##_t>(sim->sparse_read(paddr, size)); \
        data = to_value_from_be(data); \
        if (!matched_trigger) { \
          matched_trigger = trigger_exception(OPERATION_LOAD, addr, data); \
          if (matched_trigger) \
            throw *matched_trigger; \
        } \
        type##_t update_data = to_target_from_value(data); \
        update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, size, reinterpret_cast<const char*>(&update_data), "read"); \
        return data; \
      } \
      target_endian<type##_t> res; \
      load_slow_path(addr, sizeof(type##_t), (uint8_t*)&res, (xlate_flags)); \
      if (proc) READ_MEM(addr, size); \
      return from_target(res); \
    }

  // load value from memory at aligned address; zero extend to register width
  load_func(uint8, load, 0)
  load_func(uint16, load, 0)
  load_func(uint32, load, 0)
  load_func(uint64, load, 0)

  // load value from guest memory at aligned address; zero extend to register width
  load_func(uint8, guest_load, RISCV_XLATE_VIRT)
  load_func(uint16, guest_load, RISCV_XLATE_VIRT)
  load_func(uint32, guest_load, RISCV_XLATE_VIRT)
  load_func(uint64, guest_load, RISCV_XLATE_VIRT)
  load_func(uint16, guest_load_x, RISCV_XLATE_VIRT|RISCV_XLATE_VIRT_HLVX)
  load_func(uint32, guest_load_x, RISCV_XLATE_VIRT|RISCV_XLATE_VIRT_HLVX)

  // load value from memory at aligned address; sign extend to register width
  load_func(int8, load, 0)
  load_func(int16, load, 0)
  load_func(int32, load, 0)
  load_func(int64, load, 0)

  // load value from guest memory at aligned address; sign extend to register width
  load_func(int8, guest_load, RISCV_XLATE_VIRT)
  load_func(int16, guest_load, RISCV_XLATE_VIRT)
  load_func(int32, guest_load, RISCV_XLATE_VIRT)
  load_func(int64, guest_load, RISCV_XLATE_VIRT)

  // template for functions that load an aligned value from memory
  #define load_func_partially_initialized(type, xlate_flags)\
    inline type##_t load_partially_initialized_##type(reg_t addr) { \
      if (unlikely(addr & (sizeof(type##_t)-1))) \
        return misaligned_load_partially_initialized(addr, sizeof(type##_t), xlate_flags); \
      type##_t res; \
      load_slow_path_partially_initialized(addr, sizeof(type##_t), (uint8_t*)&res, xlate_flags); \
      return res; \
    }

  load_func_partially_initialized(uint8, 0)
  load_func_partially_initialized(uint64, 0)

  // template for functions that store an aligned value to memory
  #define store_func(type, prefix, xlate_flags) \
    void prefix##_##type(reg_t addr, type##_t val) { \
      if (unlikely(addr & (sizeof(type##_t)-1))) \
        return misaligned_store(addr, val, sizeof(type##_t), xlate_flags); \
      reg_t vpn = addr >> PGSHIFT; \
      type##_t data = to_target_from_value(val); \
      reg_t size = sizeof(type##_t); \
      if ((xlate_flags) == 0 && likely(tlb_store_tag[vpn % TLB_ENTRIES] == vpn)) { \
        reg_t paddr = tlb_data[vpn % TLB_ENTRIES].target_offset + addr; \
        update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, size, reinterpret_cast<const char*>(&data), "write"); \
        sim->sparse_write_with_initialization(paddr, (const uint8_t*)&data, size); \
      } \
      else if ((xlate_flags) == 0 && unlikely(tlb_store_tag[vpn % TLB_ENTRIES] == (vpn | TLB_CHECK_TRIGGERS))) { \
        if (!matched_trigger) { \
          matched_trigger = trigger_exception(OPERATION_STORE, addr, val); \
          if (matched_trigger) \
            throw *matched_trigger; \
        } \
        reg_t paddr = tlb_data[vpn % TLB_ENTRIES].target_offset + addr; \
        update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, size, reinterpret_cast<const char*>(&data), "write"); \
        sim->sparse_write_with_initialization(paddr, (const uint8_t*)&data, size); \
      } \
      else { \
       store_slow_path(addr, sizeof(type##_t), (const uint8_t*)&data, (xlate_flags)); \
      } \
    }

  // template for functions that perform an atomic memory operation
  #define amo_func(type) \
    template<typename op> \
    type##_t amo_##type(reg_t addr, op f) { \
      try { \
        auto lhs = load_##type(addr, true); \
        store_##type(addr, f(lhs)); \
        return lhs; \
      } catch (trap_load_address_misaligned& t) { \
        /* AMO faults should be reported as store faults */ \
        throw trap_store_address_misaligned(t.has_gva(), t.get_tval(), t.get_tval2(), t.get_tinst()); \
      } catch (trap_load_page_fault& t) { \
        /* AMO faults should be reported as store faults */ \
        throw trap_store_page_fault(t.has_gva(), t.get_tval(), t.get_tval2(), t.get_tinst()); \
      } catch (trap_load_access_fault& t) { \
        /* AMO faults should be reported as store faults */ \
        throw trap_store_access_fault(t.has_gva(), t.get_tval(), t.get_tval2(), t.get_tinst()); \
      } catch (trap_load_guest_page_fault& t) { \
        /* AMO faults should be reported as store faults */ \
        throw trap_store_guest_page_fault(t.get_tval(), t.get_tval2(), t.get_tinst()); \
      } \
    }

  void store_float128(reg_t addr, float128_t val)
  {
#ifndef RISCV_ENABLE_MISALIGNED
    if (unlikely(addr & (sizeof(float128_t)-1)))
      throw trap_store_address_misaligned((proc) ? proc->state.v : false, addr, 0, 0);
#endif
    store_uint64(addr, val.v[0]);
    store_uint64(addr + 8, val.v[1]);
  }

  float128_t load_float128(reg_t addr)
  {
#ifndef RISCV_ENABLE_MISALIGNED
    if (unlikely(addr & (sizeof(float128_t)-1)))
      throw trap_load_address_misaligned((proc) ? proc->state.v : false, addr, 0, 0);
#endif
    return (float128_t){load_uint64(addr), load_uint64(addr + 8)};
  }

  // store value to memory at aligned address
  store_func(uint8, store, 0)
  store_func(uint16, store, 0)
  store_func(uint32, store, 0)
  store_func(uint64, store, 0)

  // store value to guest memory at aligned address
  store_func(uint8, guest_store, RISCV_XLATE_VIRT)
  store_func(uint16, guest_store, RISCV_XLATE_VIRT)
  store_func(uint32, guest_store, RISCV_XLATE_VIRT)
  store_func(uint64, guest_store, RISCV_XLATE_VIRT)

  // perform an atomic memory operation at an aligned address
  amo_func(uint32)
  amo_func(uint64)

  static const size_t LOAD_RESERVATION_SIZE = 8;

  inline void yield_load_reservation()
  {
    sim->sparse_unreserve(load_reservation_address, LOAD_RESERVATION_SIZE);
    load_reservation_address = (reg_t)-1;
  }

  inline void acquire_load_reservation(reg_t vaddr)
  {
    load_reservation_address = translate(vaddr, LOAD_RESERVATION_SIZE, LOAD, 0);
    sim->sparse_reserve(load_reservation_address, LOAD_RESERVATION_SIZE);
    refill_tlb(vaddr, load_reservation_address, 0ull /*host_addr*/, LOAD);
    return;
  }

  inline void load_reserved_address_misaligned(reg_t vaddr)
  {
    bool gva = proc ? proc->state.v : false;
#ifdef RISCV_ENABLE_MISALIGNED
    throw trap_load_access_fault(gva, vaddr, 0, 0);
#else
    throw trap_load_address_misaligned(gva, vaddr, 0, 0);
#endif
  }

  inline void store_conditional_address_misaligned(reg_t vaddr)
  {
    bool gva = proc ? proc->state.v : false;
#ifdef RISCV_ENABLE_MISALIGNED
    throw trap_store_access_fault(gva, vaddr, 0, 0);
#else
    throw trap_store_address_misaligned(gva, vaddr, 0, 0);
#endif
  }

  inline bool check_load_reservation(reg_t vaddr, size_t size)
  {
    if (vaddr & (size-1))
      store_conditional_address_misaligned(vaddr);

    reg_t paddr = translate(vaddr, LOAD_RESERVATION_SIZE, STORE, 0);
    refill_tlb(vaddr, paddr, 0ull /*host_addr*/, STORE);
    return (paddr == load_reservation_address) and (sim->sparse_is_reserved(load_reservation_address, LOAD_RESERVATION_SIZE));
  }

  static const reg_t ICACHE_ENTRIES = 1024;

  inline size_t icache_index(reg_t addr)
  {
    return (addr / PC_ALIGN) % ICACHE_ENTRIES;
  }

  inline icache_entry_t* refill_icache(reg_t addr, icache_entry_t* entry)
  {
    auto tlb_entry = translate_insn_addr(addr);
    uint16_t insn_buf = 0;
    uint64_t load_buff = 0ull;
    uint64_t muh_paddr = tlb_entry.target_offset + addr;
    size_t len = sizeof(uint16_t);
    load_buff = sim->sparse_read(muh_paddr, len); 
    reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
    reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 

    insn_bits_t insn = from_le(insn_buf); 

    int length = insn_length(insn);

    if (likely(length == 4)) {
      load_buff = sim->sparse_read(muh_paddr + 2, len); 
      reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
      reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 
      insn_buf = from_le(insn_buf);
      insn |= (insn_bits_t)(const int16_t)insn_buf << 16;
    } else if (length == 2) {
      insn = (int16_t)insn;

    } else if (length == 6) {
      load_buff = sim->sparse_read(muh_paddr + 4, len); 
      reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
      reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 
      insn_buf = from_le(insn_buf); 
      insn |= (insn_bits_t)(const int16_t)insn_buf << 32;

      load_buff = sim->sparse_read(muh_paddr + 2, len); 
      reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
      reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 
      insn_buf = from_le(insn_buf); 
      insn |= (insn_bits_t)(const uint16_t)insn_buf << 16;
    } else {
      static_assert(sizeof(insn_bits_t) == 8, "insn_bits_t must be uint64_t");
      load_buff = sim->sparse_read(muh_paddr + 6, len); 
      reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
      reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 
      insn_buf = from_le(insn_buf); 
      insn |= (insn_bits_t)(const int16_t)insn_buf << 48;

      load_buff = sim->sparse_read(muh_paddr + 4, len); 
      reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
      reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 
      insn_buf = from_le(insn_buf); 
      insn |= (insn_bits_t)(const uint16_t)insn_buf << 32;

      load_buff = sim->sparse_read(muh_paddr + 2, len); 
      reinterpret_cast<uint8_t*>(&insn_buf)[0] = reinterpret_cast<uint8_t*>(&load_buff)[1]; 
      reinterpret_cast<uint8_t*>(&insn_buf)[1] = reinterpret_cast<uint8_t*>(&load_buff)[0]; 
      insn_buf = from_le(insn_buf); 
      insn |= (insn_bits_t)(const uint16_t)insn_buf << 16;
    }

    insn_fetch_t fetch = {proc->decode_insn(insn), insn};
    entry->tag = addr;
    entry->next = &icache[icache_index(addr + length)];
    entry->data = fetch;

    reg_t paddr = tlb_entry.target_offset + addr;;
    if (tracer.interested_in_range(paddr, paddr + 1, FETCH)) {
      entry->tag = -1;
      tracer.trace(paddr, length, FETCH);
    }
    return entry;
  }

  inline icache_entry_t* access_icache(reg_t addr)
  {
    icache_entry_t* entry = &icache[icache_index(addr)];
    if (likely(entry->tag == addr))
      return entry;
    return refill_icache(addr, entry);
  }

  inline insn_fetch_t load_insn(reg_t addr)
  {
    icache_entry_t entry;
    return refill_icache(addr, &entry)->data;
  }

  void flush_tlb();
  void flush_icache();

  void register_memtracer(memtracer_t*);

  int is_dirty_enabled()
  {
#ifdef RISCV_ENABLE_DIRTY
    return 1;
#else
    return 0;
#endif
  }

  int is_misaligned_enabled()
  {
#ifdef RISCV_ENABLE_MISALIGNED
    return 1;
#else
    return 0;
#endif
  }

  void set_target_big_endian(bool enable)
  {
#ifdef RISCV_ENABLE_DUAL_ENDIAN
    target_big_endian = enable;
#else
    assert(enable == false);
#endif
  }

  bool is_target_big_endian()
  {
    return target_big_endian;
  }

  template<typename T> inline T from_target(target_endian<T> n) const
  {
    return target_big_endian? n.from_be() : n.from_le();
  }

  template<typename T> inline target_endian<T> to_target(T n) const
  {
    return target_big_endian? target_endian<T>::to_be(n) : target_endian<T>::to_le(n);
  }

  template<typename T> inline T to_target_from_value(T n) const
  {
    return target_big_endian? to_be(n) : to_le(n);
  }

  template<typename T> inline T to_value_from_be(T n) const
  {
    return target_big_endian? n : from_be(n);
  }


  reg_t translate(reg_t addr, reg_t len, access_type type, uint32_t xlate_flags);

  // Translate a VA to a PA by performing a page table walk but don't set any state bits
  // and instead of throwing exceptions, return codes are used.
  //
  // Does a pmp check on the recovered PA.
  //
  //    returns:
  //        0 - walk was successful
  //        1 - PMP problem with PA after address translation somehow
  //        2 - access exception while trying to check pmp status of page table entry PA
  //        3 - walk was unsuccessful and access type was FETCH
  //        4 - walk was unsuccessful and access type was LOAD
  //        5 - walk was unsuccessful and access type was STORE
  //        6 - walk was unsuccessful and access type was not any of the above
  //        7 - walk would have been successful had paddr_ptr not been a null pointer
  int translate_api(reg_t addr, reg_t* paddr, uint64_t* pmp_info, reg_t len, access_type type, uint32_t xlate_flags);

private:
  simif_t* sim;
  processor_t* proc;
  memtracer_list_t tracer;
  reg_t load_reservation_address;
  uint16_t fetch_temp;

  // implement an instruction cache for simulator performance
  icache_entry_t icache[ICACHE_ENTRIES];

  // implement a TLB for simulator performance
  static const reg_t TLB_ENTRIES = 256;
  // If a TLB tag has TLB_CHECK_TRIGGERS set, then the MMU must check for a
  // trigger match before completing an access.
  static const reg_t TLB_CHECK_TRIGGERS = reg_t(1) << 63;
  tlb_entry_t tlb_data[TLB_ENTRIES];
  reg_t tlb_insn_tag[TLB_ENTRIES];
  reg_t tlb_load_tag[TLB_ENTRIES];
  reg_t tlb_store_tag[TLB_ENTRIES];

  // finish translation on a TLB miss and update the TLB
  tlb_entry_t refill_tlb(reg_t vaddr, reg_t paddr, char* host_addr, access_type type);
  const char* fill_from_mmio(reg_t vaddr, reg_t paddr);

  // perform a stage2 translation for a given guest address
  reg_t s2xlate(reg_t gva, reg_t gpa, access_type type, access_type trap_type, bool virt, bool hlvx);

  // perform a page table walk for a given VA; set referenced/dirty bits
  reg_t walk(reg_t addr, access_type type, reg_t prv, bool virt, bool hlvx);

  // perform a page table walk but don't set any state bits
  // and instead of throwing exceptions, return codes are used:
  //
  //    returns:
  //        0 - walk was successful
  //        2 - access exception while trying to check pmp status of page table entry PA
  //        3 - walk was unsuccessful and access type was FETCH
  //        4 - walk was unsuccessful and access type was LOAD
  //        5 - walk was unsuccessful and access type was STORE
  //        6 - walk was unsuccessful and access type was not any of the above
  //        7 - walk would have been successful had paddr_ptr not been a null pointer
  int walk_api(reg_t addr, reg_t* paddr_ptr, access_type type, reg_t prv, bool virt, bool hlvx);

  // handle uncommon cases: TLB misses, page faults, MMIO
  tlb_entry_t fetch_slow_path(reg_t addr);
  void load_slow_path(reg_t addr, reg_t len, uint8_t* bytes, uint32_t xlate_flags);
  void load_slow_path_partially_initialized(reg_t addr, reg_t len, uint8_t* bytes, uint32_t xlate_flags);
  void store_slow_path(reg_t addr, reg_t len, const uint8_t* bytes, uint32_t xlate_flags);
  void initialize_slow_path(reg_t addr, reg_t len, const uint8_t* bytes, uint32_t xlate_flags);
  //reg_t translate(reg_t addr, reg_t len, access_type type);

  // ITLB lookup
  inline tlb_entry_t translate_insn_addr(reg_t addr) {
    reg_t vpn = addr >> PGSHIFT;
    if (likely(tlb_insn_tag[vpn % TLB_ENTRIES] == vpn))
      return tlb_data[vpn % TLB_ENTRIES];
    tlb_entry_t result;
    if (unlikely(tlb_insn_tag[vpn % TLB_ENTRIES] != (vpn | TLB_CHECK_TRIGGERS))) {
      result = fetch_slow_path(addr);
    } else {
      result = tlb_data[vpn % TLB_ENTRIES];
    }
    if (unlikely(tlb_insn_tag[vpn % TLB_ENTRIES] == (vpn | TLB_CHECK_TRIGGERS))) {
      reg_t paddr = tlb_data[vpn % TLB_ENTRIES].target_offset + addr;

      uint16_t load_buff = 0;
      load_buff = static_cast<uint16_t>(sim->sparse_read(paddr, sizeof(uint16_t)));

      int match = proc->trigger_match(OPERATION_EXECUTE, addr, from_be(load_buff));
      if (match >= 0) {
        throw trigger_matched_t(match, OPERATION_EXECUTE, addr, from_be(load_buff));
      }
    }
    return result;
  }

  //possibly remove
  //inline const uint16_t* translate_insn_addr_to_host(reg_t addr) {
  //  return (uint16_t*)(translate_insn_addr(addr).host_offset + addr);
  //}

  inline trigger_matched_t *trigger_exception(trigger_operation_t operation,
      reg_t address, reg_t data)
  {
    if (!proc) {
      return NULL;
    }
    int match = proc->trigger_match(operation, address, data);
    if (match == -1)
      return NULL;
    if (proc->state.mcontrol[match].timing == 0) {
      throw trigger_matched_t(match, operation, address, data);
    }
    return new trigger_matched_t(match, operation, address, data);
  }

  reg_t pmp_homogeneous(reg_t addr, reg_t len);
  bool pmp_ok(reg_t addr, reg_t len, access_type type, reg_t mode);
  bool pmp_ok_api(reg_t addr, reg_t* pmpaddr_ptr, uint8_t* pmpcfg_ptr, reg_t len, access_type type, reg_t mode);

#ifdef RISCV_ENABLE_DUAL_ENDIAN
  bool target_big_endian;
#else
  static const bool target_big_endian = false;
#endif
  bool check_triggers_fetch;
  bool check_triggers_load;
  bool check_triggers_store;
  // The exception describing a matched trigger, or NULL.
  trigger_matched_t *matched_trigger;

  friend class processor_t;
};

struct vm_info {
  int levels;
  int idxbits;
  int widenbits;
  int ptesize;
  reg_t ptbase;
};

inline vm_info decode_vm_info(int xlen, bool stage2, reg_t prv, reg_t satp)
{
  if (prv == PRV_M) {
    return {0, 0, 0, 0, 0};
  } else if (!stage2 && prv <= PRV_S && xlen == 32) {
    switch (get_field(satp, SATP32_MODE)) {
      case SATP_MODE_OFF: return {0, 0, 0, 0, 0};
      case SATP_MODE_SV32: return {2, 10, 0, 4, (satp & SATP32_PPN) << PGSHIFT};
      default: abort();
    }
  } else if (!stage2 && prv <= PRV_S && xlen == 64) {
    switch (get_field(satp, SATP64_MODE)) {
      case SATP_MODE_OFF: return {0, 0, 0, 0, 0};
      case SATP_MODE_SV39: return {3, 9, 0, 8, (satp & SATP64_PPN) << PGSHIFT};
      case SATP_MODE_SV48: return {4, 9, 0, 8, (satp & SATP64_PPN) << PGSHIFT};
      case SATP_MODE_SV57: return {5, 9, 0, 8, (satp & SATP64_PPN) << PGSHIFT};
      case SATP_MODE_SV64: return {6, 9, 0, 8, (satp & SATP64_PPN) << PGSHIFT};
      default: abort();
    }
  } else if (stage2 && xlen == 32) {
    switch (get_field(satp, HGATP32_MODE)) {
      case HGATP_MODE_OFF: return {0, 0, 0, 0, 0};
      case HGATP_MODE_SV32X4: return {2, 10, 2, 4, (satp & HGATP32_PPN) << PGSHIFT};
      default: abort();
    }
  } else if (stage2 && xlen == 64) {
    switch (get_field(satp, HGATP64_MODE)) {
      case HGATP_MODE_OFF: return {0, 0, 0, 0, 0};
      case HGATP_MODE_SV39X4: return {3, 9, 2, 8, (satp & HGATP64_PPN) << PGSHIFT};
      case HGATP_MODE_SV48X4: return {4, 9, 2, 8, (satp & HGATP64_PPN) << PGSHIFT};
      default: abort();
    }
  } else {
    abort();
  }
}

#endif
