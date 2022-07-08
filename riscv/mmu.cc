// See LICENSE for license details.

#include "mmu.h"
#include "arith.h"
#include "simif.h"
#include "processor.h"

//DEBUG
#include <iostream>

mmu_t::mmu_t(simif_t* sim, processor_t* proc)
 : sim(sim), proc(proc),
#ifdef RISCV_ENABLE_DUAL_ENDIAN
  target_big_endian(false),
#endif
  check_triggers_fetch(false),
  check_triggers_load(false),
  check_triggers_store(false),
  matched_trigger(NULL)
{
  flush_tlb();
  yield_load_reservation();
}

mmu_t::~mmu_t()
{
}

void mmu_t::flush_icache()
{
  for (size_t i = 0; i < ICACHE_ENTRIES; i++)
    icache[i].tag = -1;
}

void mmu_t::flush_tlb()
{
  memset(tlb_insn_tag, -1, sizeof(tlb_insn_tag));
  memset(tlb_load_tag, -1, sizeof(tlb_load_tag));
  memset(tlb_store_tag, -1, sizeof(tlb_store_tag));

  flush_icache();
}

static void throw_access_exception(bool virt, reg_t addr, access_type type)
{
  switch (type) {
    case FETCH: throw trap_instruction_access_fault(virt, addr, 0, 0);
    case LOAD: throw trap_load_access_fault(virt, addr, 0, 0);
    case STORE: throw trap_store_access_fault(virt, addr, 0, 0);
    default: abort();
  }
}

reg_t mmu_t::translate(reg_t addr, reg_t len, access_type type, uint32_t xlate_flags)
{
  if (!proc)
    return addr;

  bool virt = proc->state.v;
  bool hlvx = xlate_flags & RISCV_XLATE_VIRT_HLVX;
  reg_t mode = proc->state.prv;
  if (type != FETCH) {
    if (!proc->state.debug_mode && get_field(proc->state.mstatus->read(), MSTATUS_MPRV)) {
      mode = get_field(proc->state.mstatus->read(), MSTATUS_MPP);
      if (get_field(proc->state.mstatus->read(), MSTATUS_MPV) && mode != PRV_M)
        virt = true;
    }
    if (xlate_flags & RISCV_XLATE_VIRT) {
      virt = true;
      mode = get_field(proc->state.hstatus->read(), HSTATUS_SPVP);
    }
  }

  reg_t paddr = walk(addr, type, mode, virt, hlvx) | (addr & (PGSIZE-1));
  if (!pmp_ok(paddr, len, type, mode))
    throw_access_exception(virt, addr, type);
  return paddr;
}

int mmu_t::translate_api(reg_t addr, reg_t* paddr, uint64_t* pmp_info, reg_t len, access_type type, uint32_t xlate_flags)
{
  int status = 0;
  if (!proc){
    status = 1;
    return status;    
  }

  bool virt = proc->state.v;
  bool hlvx = xlate_flags & RISCV_XLATE_VIRT_HLVX;
  reg_t mode = proc->state.prv;
  if (type != FETCH) {
    if (!proc->state.debug_mode && get_field(proc->state.mstatus->read(), MSTATUS_MPRV)) {
      mode = get_field(proc->state.mstatus->read(), MSTATUS_MPP);
      if (get_field(proc->state.mstatus->read(), MSTATUS_MPV) && mode != PRV_M)
        virt = true;
    }
    if (xlate_flags & RISCV_XLATE_VIRT) {
      virt = true;
      mode = get_field(proc->state.hstatus->read(), HSTATUS_SPVP);
    }
  }

  reg_t temp_paddr = 0ull;
  status = walk_api(addr, &temp_paddr, type, mode, virt, hlvx);
  temp_paddr |= (addr & (PGSIZE-1));

  reg_t temp_pmpaddr = 0ull;
  uint8_t temp_pmpcfg = 0;
  if (status == 0 && !pmp_ok_api(temp_paddr, &temp_pmpaddr, &temp_pmpcfg, len, type, mode))
  {
    status = 1; // Failed pmp check, either there was no match or there was only a partial match of the PMP requriements for that physical address.
  }

  if(pmp_info != nullptr)
  {
    *pmp_info = (temp_pmpaddr << 6) | (uint64_t)temp_pmpcfg; // This implies a 56 bit address 
    std::cerr << "In translate_api, temp_pmpaddr is: " << std::hex << temp_pmpaddr << " while temp_pmpcfg is: " << std::hex << (uint64_t)temp_pmpcfg << std::endl;
  }

  *paddr = temp_paddr;
  return status;
}

tlb_entry_t mmu_t::fetch_slow_path(reg_t vaddr)
{
  reg_t paddr = translate(vaddr, sizeof(fetch_temp), FETCH, 0);
  return refill_tlb(vaddr, paddr, 0 /*host_addr*/, FETCH);
}

reg_t reg_from_bytes(size_t len, const uint8_t* bytes)
{
  switch (len) {
    case 1:
      return bytes[0];
    case 2:
      return bytes[0] |
        (((reg_t) bytes[1]) << 8);
    case 4:
      return bytes[0] |
        (((reg_t) bytes[1]) << 8) |
        (((reg_t) bytes[2]) << 16) |
        (((reg_t) bytes[3]) << 24);
    case 8:
      return bytes[0] |
        (((reg_t) bytes[1]) << 8) |
        (((reg_t) bytes[2]) << 16) |
        (((reg_t) bytes[3]) << 24) |
        (((reg_t) bytes[4]) << 32) |
        (((reg_t) bytes[5]) << 40) |
        (((reg_t) bytes[6]) << 48) |
        (((reg_t) bytes[7]) << 56);
  }
  abort();
}

void mmu_t::load_slow_path_partially_initialized(reg_t addr, reg_t len, uint8_t* bytes, uint32_t xlate_flags)
{
  reg_t paddr = translate(addr, len, LOAD, xlate_flags);
  sim->sparse_read_partially_initialized(paddr, len, bytes);

  update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, len, reinterpret_cast<const char*>(bytes), "read");

  if (tracer.interested_in_range(paddr, paddr + PGSIZE, LOAD))
    tracer.trace(paddr, len, LOAD);
  else
    refill_tlb(addr, paddr, 0 /*host_addr*/, LOAD);
  
  if (!matched_trigger) {
    reg_t data = reg_from_bytes(len, bytes);
    matched_trigger = trigger_exception(OPERATION_LOAD, addr, data);
    if (matched_trigger)
      throw *matched_trigger;
  }
}

void mmu_t::load_slow_path(reg_t addr, reg_t len, uint8_t* bytes, uint32_t xlate_flags)
{
  reg_t paddr = translate(addr, len, LOAD, xlate_flags);
  uint64_t buff = 0ull;

  buff = sim->sparse_read(paddr, len);
  for(size_t byte_idx = 0; byte_idx < len; ++ byte_idx)
  {
    size_t buff_idx = len - 1 - byte_idx;
    if (target_big_endian) {
      buff_idx = byte_idx;
    }

    bytes[byte_idx] = reinterpret_cast<uint8_t*>(&buff)[buff_idx];
  }

  update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, len, reinterpret_cast<const char*>(bytes), "read");

  if (tracer.interested_in_range(paddr, paddr + PGSIZE, LOAD))
    tracer.trace(paddr, len, LOAD);
  else
    refill_tlb(addr, paddr, 0 /*host_addr*/, LOAD);

  if (!matched_trigger) {
    reg_t data = reg_from_bytes(len, bytes);
    matched_trigger = trigger_exception(OPERATION_LOAD, addr, data);
    if (matched_trigger)
      throw *matched_trigger;
  }
}

void mmu_t::initialize_slow_path(reg_t addr, reg_t len, const uint8_t* bytes, uint32_t xlate_flags)
{
  reg_t paddr = translate(addr, len, STORE, xlate_flags);

  update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, len, reinterpret_cast<const char*>(bytes), "write");

  if (!matched_trigger) {
    reg_t data = reg_from_bytes(len, bytes);
    matched_trigger = trigger_exception(OPERATION_STORE, addr, data);
    if (matched_trigger)
      throw *matched_trigger;
  }

  // Initialize the memory if necessary
  if(! sim->sparse_is_pa_initialized(paddr, len))
  {
      uint64_t attrs = 0ull;
      sim->sparse_initialize_pa(paddr, bytes, reinterpret_cast<const uint8_t*>(&attrs), len, Force::EMemDataType::Both);
  }
  else
  {//perform the write
      sim->sparse_write(paddr, bytes, len);
  }
  if (tracer.interested_in_range(paddr, paddr + PGSIZE, STORE))
    tracer.trace(paddr, len, STORE);
  else
    refill_tlb(addr, paddr, 0 /*host_addr*/, STORE);
}

void mmu_t::store_slow_path(reg_t addr, reg_t len, const uint8_t* bytes, uint32_t xlate_flags)
{
  reg_t paddr = translate(addr, len, STORE, xlate_flags);

  update_generator_memory(nullptr != proc ? proc->id : 0xffffffffu, addr, 0, paddr, len, reinterpret_cast<const char*>(bytes), "write");

  if (!matched_trigger) {
    reg_t data = reg_from_bytes(len, bytes);
    matched_trigger = trigger_exception(OPERATION_STORE, addr, data);
    if (matched_trigger)
      throw *matched_trigger;
  }

  // Initialize the memory if necessary
  if(unlikely(! sim->sparse_is_pa_initialized(paddr, len)))
  {
      uint64_t attrs = 0ull;
      sim->sparse_initialize_pa(paddr, bytes, reinterpret_cast<const uint8_t*>(&attrs), len, Force::EMemDataType::Both);
  }
  else
  {//perform the write
    sim->sparse_write(paddr, bytes, len);
  }

  if (tracer.interested_in_range(paddr, paddr + PGSIZE, STORE))
    tracer.trace(paddr, len, STORE);
  else
    refill_tlb(addr, paddr, 0 /*host_addr*/, STORE);
}

tlb_entry_t mmu_t::refill_tlb(reg_t vaddr, reg_t paddr, char* host_addr, access_type type)
{
  reg_t idx = (vaddr >> PGSHIFT) % TLB_ENTRIES;
  reg_t expected_tag = vaddr >> PGSHIFT;

  tlb_entry_t entry = {host_addr - vaddr, paddr - vaddr};

  if (proc && get_field(proc->state.mstatus->read(), MSTATUS_MPRV))
    return entry;

  if ((tlb_load_tag[idx] & ~TLB_CHECK_TRIGGERS) != expected_tag)
    tlb_load_tag[idx] = -1;
  if ((tlb_store_tag[idx] & ~TLB_CHECK_TRIGGERS) != expected_tag)
    tlb_store_tag[idx] = -1;
  if ((tlb_insn_tag[idx] & ~TLB_CHECK_TRIGGERS) != expected_tag)
    tlb_insn_tag[idx] = -1;

  if ((check_triggers_fetch && type == FETCH) ||
      (check_triggers_load && type == LOAD) ||
      (check_triggers_store && type == STORE))
    expected_tag |= TLB_CHECK_TRIGGERS;

  if (pmp_homogeneous(paddr & ~reg_t(PGSIZE - 1), PGSIZE)) {
    if (type == FETCH) tlb_insn_tag[idx] = expected_tag;
    else if (type == STORE) tlb_store_tag[idx] = expected_tag;
    else tlb_load_tag[idx] = expected_tag;
  }

  tlb_data[idx] = entry;
  return entry;
}

bool mmu_t::pmp_ok(reg_t addr, reg_t len, access_type type, reg_t mode)
{
  if (!proc || proc->n_pmp == 0)
    return true;

  for (size_t i = 0; i < proc->n_pmp; i++) {
    // Check each 4-byte sector of the access
    bool any_match = false;
    bool all_match = true;
    for (reg_t offset = 0; offset < len; offset += 1 << PMP_SHIFT) {
      reg_t cur_addr = addr + offset;
      bool match = proc->state.pmpaddr[i]->match4(cur_addr);
      any_match |= match;
      all_match &= match;
    }

    if (any_match) {
      // If the PMP matches only a strict subset of the access, fail it
      if (!all_match)
        return false;

      return proc->state.pmpaddr[i]->access_ok(type, mode);
    }
  }

  return mode == PRV_M;
}

bool mmu_t::pmp_ok_api(reg_t addr, reg_t* pmpaddr_ptr, uint8_t* pmpcfg_ptr, reg_t len, access_type type, reg_t mode)
{
  if (!proc || proc->n_pmp == 0)
    return true;

  for (size_t i = 0; i < proc->n_pmp; i++) {
    if(pmpaddr_ptr != nullptr && pmpcfg_ptr != nullptr) {
      *pmpaddr_ptr = proc->state.pmpaddr[i]->get_tor_paddr();
      *pmpcfg_ptr = proc->state.pmpaddr[i]->get_cfg();
    }

    // Check each 4-byte sector of the access
    bool any_match = false;
    bool all_match = true;
    for (reg_t offset = 0; offset < len; offset += 1 << PMP_SHIFT) {
      reg_t cur_addr = addr + offset;
      bool match = proc->state.pmpaddr[i]->match4(cur_addr);
      any_match |= match;
      all_match &= match;
    }

    if (any_match) {
      // If the PMP matches only a strict subset of the access, fail it
      if (!all_match)
        return false;

      return proc->state.pmpaddr[i]->access_ok(type, mode);
    }
  }

  return mode == PRV_M;
}

reg_t mmu_t::pmp_homogeneous(reg_t addr, reg_t len)
{
  if ((addr | len) & (len - 1))
    abort();

  if (!proc)
    return true;

  for (size_t i = 0; i < proc->n_pmp; i++)
    if (proc->state.pmpaddr[i]->subset_match(addr, len))
      return false;

  return true;
}

reg_t mmu_t::s2xlate(reg_t gva, reg_t gpa, access_type type, access_type trap_type, bool virt, bool hlvx)
{
  if (!virt)
    return gpa;

  vm_info vm = decode_vm_info(proc->get_const_xlen(), true, 0, proc->get_state()->hgatp);
  if (vm.levels == 0)
    return gpa;

  bool mxr = proc->state.sstatus->readvirt(false) & MSTATUS_MXR;

  reg_t base = vm.ptbase;
  for (int i = vm.levels - 1; i >= 0; i--) {
    int ptshift = i * vm.idxbits;
    int idxbits = (i == (vm.levels - 1)) ? vm.idxbits + vm.widenbits : vm.idxbits;
    reg_t idx = (gpa >> (PGSHIFT + ptshift)) & ((reg_t(1) << idxbits) - 1);

    // check that physical address of PTE is legal
    auto pte_paddr = base + idx * vm.ptesize;
    bool pte_init = sim->sparse_is_pa_initialized(pte_paddr, vm.ptesize);
    if (!pte_init || !pmp_ok(pte_paddr, vm.ptesize, LOAD, PRV_S)) {
      throw_access_exception(virt, gva, trap_type);
    }

    uint64_t ppte_val = 0ull;
    if (vm.ptesize == 4) {
       ppte_val = sim->sparse_read(pte_paddr, sizeof(uint32_t));
    } else {
       ppte_val = sim->sparse_read(pte_paddr, sizeof(uint64_t));
    }

    reg_t pte = vm.ptesize == 4 ? from_target(*(target_endian<uint32_t>*)(&ppte_val)) : from_target(*(target_endian<uint64_t>*)(&ppte_val));
    reg_t ppn = (pte & ~reg_t(PTE_ATTR)) >> PTE_PPN_SHIFT;

    if (pte & PTE_RSVD) {
      break;
    } else if (PTE_TABLE(pte)) { // next level of page table
      if (pte & (PTE_D | PTE_A | PTE_U | PTE_N | PTE_PBMT))
        break;
      base = ppn << PGSHIFT;
    } else if (!(pte & PTE_V) || (!(pte & PTE_R) && (pte & PTE_W))) {
      break;
    } else if (!(pte & PTE_U)) {
      break;
    } else if (type == FETCH || hlvx ? !(pte & PTE_X) :
               type == LOAD          ? !(pte & PTE_R) && !(mxr && (pte & PTE_X)) :
                                       !((pte & PTE_R) && (pte & PTE_W))) {
      break;
    } else if ((ppn & ((reg_t(1) << ptshift) - 1)) != 0) {
      break;
    } else {
      reg_t ad = PTE_A | ((type == STORE) * PTE_D);
#ifdef RISCV_ENABLE_DIRTY
      // set accessed and possibly dirty bits.
      if ((pte & ad) != ad) {
        if (!pmp_ok(pte_paddr, vm.ptesize, STORE, PRV_S))
          throw_access_exception(virt, gva, trap_type);
        *(target_endian<uint32_t>*)ppte |= to_target((uint32_t)ad);
      }
#else
      // take exception if access or possibly dirty bit is not set.
      if ((pte & ad) != ad)
        break;
#endif
      reg_t vpn = gpa >> PGSHIFT;
      reg_t page_mask = (reg_t(1) << PGSHIFT) - 1;

      int napot_bits = ((pte & PTE_N) ? (ctz(ppn) + 1) : 0);
      if (((pte & PTE_N) && (ppn == 0 || i != 0)) || (napot_bits != 0 && napot_bits != 4))
        break;

      reg_t page_base = ((ppn & ~((reg_t(1) << napot_bits) - 1))
                        | (vpn & ((reg_t(1) << napot_bits) - 1))
                        | (vpn & ((reg_t(1) << ptshift) - 1))) << PGSHIFT;
      return page_base | (gpa & page_mask);
    }
  }

  switch (trap_type) {
    case FETCH: throw trap_instruction_guest_page_fault(gva, gpa >> 2, 0);
    case LOAD: throw trap_load_guest_page_fault(gva, gpa >> 2, 0);
    case STORE: throw trap_store_guest_page_fault(gva, gpa >> 2, 0);
    default: abort();
  }
}

reg_t mmu_t::walk(reg_t addr, access_type type, reg_t mode, bool virt, bool hlvx)
{
  //std::cout << "mmu_t::walk addr=0x" << std::hex << addr << " mode=0x" << mode << std::endl;
  reg_t page_mask = (reg_t(1) << PGSHIFT) - 1;
  reg_t satp = proc->get_state()->satp->readvirt(virt);
  vm_info vm = decode_vm_info(proc->get_const_xlen(), false, mode, satp);
  if (vm.levels == 0)
    return s2xlate(addr, addr & ((reg_t(2) << (proc->xlen-1))-1), type, type, virt, hlvx) & ~page_mask; // zero-extend from xlen

  //std::cout << "mmu_t::walk vm.ptbase=0x" << std::hex << vm.ptbase << " levels=0x" << vm.levels << std::endl;

  bool s_mode = mode == PRV_S;
  bool sum = proc->state.sstatus->readvirt(virt) & MSTATUS_SUM;
  bool mxr = (proc->state.sstatus->readvirt(false) | proc->state.sstatus->readvirt(virt)) & MSTATUS_MXR;

  // verify bits xlen-1:va_bits-1 are all equal
  int va_bits = PGSHIFT + vm.levels * vm.idxbits;
  reg_t mask = (reg_t(1) << (proc->xlen - (va_bits-1))) - 1;
  reg_t masked_msbs = (addr >> (va_bits-1)) & mask;
  if (masked_msbs != 0 && masked_msbs != mask)
    vm.levels = 0;

  //std::cout << "mmu_t::walk va_bits=0x" << std::hex << va_bits << " xlen=0x" << proc->xlen << " mask=0x" << mask << " masked_msbs=0x" << masked_msbs << " levels=0x" << vm.levels << std::endl;

  reg_t base = vm.ptbase;
  for (int i = vm.levels - 1; i >= 0; i--) {
    int ptshift = i * vm.idxbits;
    //std::cout << "mmu_t::walk i=0x" << std::hex << i << " ptshift=0x" << ptshift << " levels=0x" << vm.levels << std::endl;
    reg_t idx = (addr >> (PGSHIFT + ptshift)) & ((1 << vm.idxbits) - 1);
    //std::cout << "mmu_t::walk idx=0x" << std::hex << idx << std::endl;
    // check that physical address of PTE is legal
    auto pte_paddr = s2xlate(addr, base + idx * vm.ptesize, LOAD, type, virt, false);
    //std::cout << "mmu_t::walk pte_paddr=0x" << std::hex << pte_paddr << std::endl;
    //auto ppte = sim->addr_to_mem(pte_paddr);
    bool ppte = sim->sparse_is_pa_initialized(pte_paddr, vm.ptesize);
    if (!ppte || !pmp_ok(pte_paddr, vm.ptesize, LOAD, PRV_S))
      throw_access_exception(virt, addr, type);

    uint64_t ppte_val = 0ull;

    if (vm.ptesize == 4) {
       // Sv32...
       uint32_t tbuf = sim->sparse_read(pte_paddr, sizeof(uint32_t));
       uint32_t ppte_reversed_val = 0ull;
       uint8_t* val = (uint8_t*)&tbuf;
       uint8_t* rev = (uint8_t*)&ppte_reversed_val;
       for (size_t i = 0; i < sizeof(uint32_t); i++) {
          rev[i] = val[sizeof(uint32_t)-1-i];
       }
       //std::cout << "mmut_t::walk ppte_reversed_val=0x" << std::hex << ppte_reversed_val << std::endl;
       ppte_val = ppte_reversed_val;
    } else { 
       //sim->sparse_read_partially_initialized(pte_paddr, sizeof(uint64_t), reinterpret_cast<uint8_t*>(ppte_val)); 
       //uint64_t buff = 0ull;
       //std::cerr << "length: " << len << " paddr: " << std::hex << paddr <<  std::endl;
       ppte_val = sim->sparse_read(pte_paddr, sizeof(uint64_t)); // In testing of the api version of this,
                                                                // it was noticed that reading in the commented out way was
                                                                // byte reversing the expected values.
       //std::cout << "mmu_t::walk ppte_val=0x" << std::hex << ppte_val << std::endl;
       uint64_t ppte_reversed_val = 0ull;
       uint8_t* val = (uint8_t*)&ppte_val;
       uint8_t* rev = (uint8_t*)&ppte_reversed_val;
       for (size_t i = 0; i < sizeof(uint64_t); i++)
       {
         rev[i] = val[sizeof(uint64_t)-1-i];
       }
       //std::cout << "mmut_t::walk ppte_reversed_val=0x" << std::hex << ppte_reversed_val << std::endl;
       ppte_val = ppte_reversed_val;
    }

    //sim->sparse_read_partially_initialized(paddr, len, bytes);
    //bool same_data_was_loaded = true;
    //for(size_t byte_idx = 0; byte_idx < sizeof(uint64_t); ++ byte_idx)
    //{
    //    //same_data_was_loaded &= (reinterpret_cast<uint8_t*>(&buff)[len - 1 -byte_idx] == bytes[byte_idx]);
    //    //assert(false && reinterpret_cast<uint8_t*>(&ppte_val)[byte_idx] == reinterpret_cast<uint8_t*>(&buff)[sizeof(uint64_t) -1 -byte_idx] && "Did not match ppte val load");
    //    reinterpret_cast<uint8_t*>(&ppte_val)[byte_idx] = reinterpret_cast<uint8_t*>(&buff)[sizeof(uint64_t) -1 -byte_idx];
    //}

    //
    //
    // These endianness conversion functions are defined in the new version, do they work for our purposes or are they redundant with the above code?
    //
    //
    reg_t pte = vm.ptesize == 4 ? from_target(*(target_endian<uint32_t>*)(&ppte_val)) : from_target(*(target_endian<uint64_t>*)(&ppte_val));
    reg_t ppn = (pte & ~reg_t(PTE_ATTR)) >> PTE_PPN_SHIFT;

    //std::cout << "mmu_t::walk pte=0x" << std::hex << pte << " ppn=0x" << ppn << std::endl;

    if (pte & PTE_RSVD) {
      break;
    } else if (PTE_TABLE(pte)) { // next level of page table
      if (pte & (PTE_D | PTE_A | PTE_U | PTE_N | PTE_PBMT))
        break;
      base = ppn << PGSHIFT;
      //std::cout << "mmu_t::walk next level table base=0x" << std::hex << base << std::endl;
    } else if ((pte & PTE_U) ? s_mode && (type == FETCH || !sum) : !s_mode) {
      //std::cout << "mmu_t::walk u bit set causing page fault" << std::endl;
      break;
    } else if (!(pte & PTE_V) || (!(pte & PTE_R) && (pte & PTE_W))) {
      //std::cout << "mmu_t::walk v bit not set, or R+W not set causing page fault" << std::endl;
      break;
    } else if (type == FETCH || hlvx ? !(pte & PTE_X) :
               type == LOAD          ? !(pte & PTE_R) && !(mxr && (pte & PTE_X)) :
                                       !((pte & PTE_R) && (pte & PTE_W))) {
      //std::cout << "mmu_t::walk non-executable, or load not readable causing page fault" << std::endl;
      break;
    } else if ((ppn & ((reg_t(1) << ptshift) - 1)) != 0) {
      reg_t test_val = ppn & ((reg_t(1) << ptshift) - 1);
      //std::cout << "mmu_t::walk misaligned superpage val=0x" << std::hex << test_val << " causing page fault" << std::endl;
      break;
    } else {
      reg_t ad = PTE_A | ((type == STORE) * PTE_D);
#ifdef RISCV_ENABLE_DIRTY
      // set accessed and possibly dirty bits.
      if ((pte & ad) != ad) {
        if (!pmp_ok(pte_paddr, vm.ptesize, STORE, PRV_S))
          throw_access_exception(virt, addr, type);
        (target_endian<uint32_t>)ppte_val |= to_target((uint32_t)ad);
        sim->sparse_write(pte_paddr, reinterpret_cast<uint8_t*>(&ppte_val), vm.ptesize); //NOTE this was written as a write from pte rather than ppte_val which doesnt match the reference code intent.
        uint32_t debug_buff = 0;
        sim->sparse_read_partially_initialized(pte_paddr, vm.ptesize, reinterpret_cast<uint8_t*>(&debug_buff));
        assert(debug_buff == (uint32_t)ppte_val && "Failed to modify ppte_val correctly");
      }
#else
      // take exception if access or possibly dirty bit is not set.
      if ((pte & ad) != ad)
      {
        //std::cout << "mmu_t::walk ad bits ad=0x" << std::hex << ad << " causing page fault" << std::endl;
        break;
      }
#endif
      // for superpage or Svnapot NAPOT mappings, make a fake leaf PTE for the TLB's benefit.
      reg_t vpn = addr >> PGSHIFT;

      int napot_bits = ((pte & PTE_N) ? (ctz(ppn) + 1) : 0);
      if (((pte & PTE_N) && (ppn == 0 || i != 0)) || (napot_bits != 0 && napot_bits != 4))
        break;

      reg_t page_base = ((ppn & ~((reg_t(1) << napot_bits) - 1))
                        | (vpn & ((reg_t(1) << napot_bits) - 1))
                        | (vpn & ((reg_t(1) << ptshift) - 1))) << PGSHIFT;
      reg_t phys = page_base | (addr & page_mask);
      reg_t value = s2xlate(addr, phys, type, type, virt, hlvx) & ~page_mask;

      //report the translation via the callback mechanism
      bool has_stage_two = (vm.levels > 1); 
      MmuEvent mmu_event(addr, value, Memtype::Normal, has_stage_two, 0, 0, 0, 0);
      update_mmu_event(&mmu_event);

      //std::cout << "mmu_t::walk end value=0x" << std::hex << value << std::endl;
      return value;
    }
  }

  switch (type) {
    case FETCH: throw trap_instruction_page_fault(virt, addr, 0, 0);
    case LOAD: throw trap_load_page_fault(virt, addr, 0, 0);
    case STORE: throw trap_store_page_fault(virt, addr, 0, 0);
    default: abort();
  }
}

int mmu_t::walk_api(reg_t addr, reg_t* paddr_ptr, access_type type, reg_t mode, bool virt, bool hlvx)
{
  reg_t page_mask = (reg_t(1) << PGSHIFT) - 1;
  reg_t satp = proc->get_state()->satp->readvirt(virt);
  vm_info vm = decode_vm_info(proc->get_const_xlen(), false, mode, satp);
  if (vm.levels == 0) {
    std::cerr << "vm.levels is zero" << std::endl; 
    *paddr_ptr = s2xlate(addr, addr & ((reg_t(2) << (proc->xlen-1))-1), type, type, virt, hlvx) & ~page_mask; // zero-extend from xlen
    return 0;
  }

  bool s_mode = mode == PRV_S;
  bool sum = proc->state.sstatus->readvirt(virt) & MSTATUS_SUM;
  bool mxr = (proc->state.sstatus->readvirt(false) | proc->state.sstatus->readvirt(virt)) & MSTATUS_MXR;

  // verify bits xlen-1:va_bits-1 are all equal
  int va_bits = PGSHIFT + vm.levels * vm.idxbits;
  reg_t mask = (reg_t(1) << (proc->xlen - (va_bits-1))) - 1;
  reg_t masked_msbs = (addr >> (va_bits-1)) & mask;
  if (masked_msbs != 0 && masked_msbs != mask)
  {
      vm.levels = 0;
      std::cerr << "Failed test that bits xlen-1:va_bits-1 are all equal" << std::endl;
  }
  else
  {
      std::cerr << "Passed test that bits xlen-1:va_bits-1 are all equal" << std::endl;
  }
  

  reg_t base = vm.ptbase;
  for (int i = vm.levels - 1; i >= 0; i--) {
    int ptshift = i * vm.idxbits;
    reg_t idx = (addr >> (PGSHIFT + ptshift)) & ((1 << vm.idxbits) - 1);

    // check that physical address of PTE is legal
    auto pte_paddr = s2xlate(addr, base + idx * vm.ptesize, LOAD, type, virt, false);

    std::cerr << "\tpte_paddr: " << std::hex << pte_paddr << std::endl;

    //auto ppte = sim->addr_to_mem(pte_paddr);
    bool ppte = true;
    if (!ppte || !pmp_ok(pte_paddr, vm.ptesize, LOAD, PRV_S))
    {
        return 2; //access_exception
    }
    //  throw_access_exception(virt, addr, type);

    uint64_t ppte_val = 0ull;

    //std::cerr << "length: " << len << " paddr: " << std::hex << paddr <<  std::endl;
    ppte_val = sim->sparse_read(pte_paddr, sizeof(uint64_t));
    //uint64_t ppte_reversed_val = 0ull;
    //uint8_t* val = (uint8_t*)&ppte_val;
    //uint8_t* rev = (uint8_t*)&ppte_reversed_val;
    //for (int i = 0; i < sizeof(uint64_t); i++)
    //{
    //  rev[i] = val[sizeof(uint64_t)-1-i];
    //}
    //ppte_val = ppte_reversed_val;

    reg_t pte = vm.ptesize == 4 ? from_target(*(target_endian<uint32_t>*)(&ppte_val)) : from_target(*(target_endian<uint64_t>*)(&ppte_val));
    reg_t ppn = (pte & ~reg_t(PTE_ATTR)) >> PTE_PPN_SHIFT;

    std::cerr << "\tpte: " << std::hex << pte << std::endl;
    std::cerr << "\tppn: " << std::hex << ppn << std::endl;

    if (pte & PTE_RSVD) {
      break;
    } else if (PTE_TABLE(pte)) { // next level of page table
      if (pte & (PTE_D | PTE_A | PTE_U | PTE_N | PTE_PBMT))
        break;
      base = ppn << PGSHIFT;
      std::cerr << "\t\tgoing another level." << std::endl;
    } else if ((pte & PTE_U) ? s_mode && (type == FETCH || !sum) : !s_mode) {
      std::cerr << "\t\tproblem 1." << std::endl;
      break;
    } else if (!(pte & PTE_V) || (!(pte & PTE_R) && (pte & PTE_W))) {
      std::cerr << "\t\tproblem 2." << std::endl;
      std::cerr << "\t\tis !(pte & PTE_V)?: " << (!(pte & PTE_V)) << std::endl;
      std::cerr << "\t\tis !(pte & PTE_R)?: " << (!(pte & PTE_R)) << std::endl;
      std::cerr << "\t\tis (pte & PTE_W)?: " << (pte & PTE_W) << std::endl;
      break;
    } else if (type == FETCH || hlvx ? !(pte & PTE_X) :
               type == LOAD          ? !(pte & PTE_R) && !(mxr && (pte & PTE_X)) :
                                       !((pte & PTE_R) && (pte & PTE_W))) {
      std::cerr << "\t\tproblem 3." << std::endl;
      break;
    } else if ((ppn & ((reg_t(1) << ptshift) - 1)) != 0) {
      std::cerr << "\t\tproblem 4." << std::endl;
      break;
    } else {
      std::cerr << "\t\tvalid path." << std::endl;
      reg_t ad = PTE_A | ((type == STORE) * PTE_D);
      // take exception if access or possibly dirty bit is not set.
      if ((pte & ad) != ad){
        std::cerr << "\t\tproblem 5." << std::endl;
        break;
      }
      // for superpage or Svnapot NAPOT mappings, make a fake leaf PTE for the TLB's benefit.
      reg_t vpn = addr >> PGSHIFT;

      int napot_bits = ((pte & PTE_N) ? (ctz(ppn) + 1) : 0);
      if (((pte & PTE_N) && (ppn == 0 || i != 0)) || (napot_bits != 0 && napot_bits != 4))
        break;

      reg_t page_base = ((ppn & ~((reg_t(1) << napot_bits) - 1))
                        | (vpn & ((reg_t(1) << napot_bits) - 1))
                        | (vpn & ((reg_t(1) << ptshift) - 1))) << PGSHIFT;
      reg_t phys = page_base | (addr & page_mask);
      reg_t value = s2xlate(addr, phys, type, type, virt, hlvx) & ~page_mask;
      if(paddr_ptr != nullptr)
      {
        *paddr_ptr = value;
        return 0;
      }
      else
      {
        // this should have been caught earlier
        return 7;
      }
    }
  }

  switch (type) {
    case FETCH: 
    {
        return 3; // instruction page fault
    }
    case LOAD: 
    {
        return 4; // load page fault
    }
    case STORE: 
    {
        return 5; // store page fault
    }
    default: 
    {
        return 6; // got here without one of the three other access types; probably not supposed to happen.
    }
  }
}

void mmu_t::register_memtracer(memtracer_t* t)
{
  flush_tlb();
  tracer.hook(t);
}
