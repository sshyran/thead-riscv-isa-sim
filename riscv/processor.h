// See LICENSE for license details.

#ifndef _RISCV_PROCESSOR_H
#define _RISCV_PROCESSOR_H

#include "decode.h"
#include "config.h"
#include "trap.h"
#include "abstract_device.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <cassert>
#include "debug_rom_defines.h"
#include "entropy_source.h"
#include "csrs.h"
#include <iostream>


class processor_t;
class mmu_t;
typedef reg_t (*insn_func_t)(processor_t*, insn_t, reg_t);
class simif_t;
class trap_t;
class extension_t;
class disassembler_t;

struct insn_desc_t
{
  insn_bits_t match;
  insn_bits_t mask;
  insn_func_t rv32;
  insn_func_t rv64;
};

// regnum, data
typedef std::unordered_map<reg_t, freg_t> commit_log_reg_t;

// addr, value, size
typedef std::vector<std::tuple<reg_t, uint64_t, uint8_t>> commit_log_mem_t;

typedef struct
{
  uint8_t prv;
  bool step;
  bool ebreakm;
  bool ebreakh;
  bool ebreaks;
  bool ebreaku;
  bool halt;
  uint8_t cause;
} dcsr_t;

typedef enum
{
  ACTION_DEBUG_EXCEPTION = MCONTROL_ACTION_DEBUG_EXCEPTION,
  ACTION_DEBUG_MODE = MCONTROL_ACTION_DEBUG_MODE,
  ACTION_TRACE_START = MCONTROL_ACTION_TRACE_START,
  ACTION_TRACE_STOP = MCONTROL_ACTION_TRACE_STOP,
  ACTION_TRACE_EMIT = MCONTROL_ACTION_TRACE_EMIT
} mcontrol_action_t;

typedef enum
{
  MATCH_EQUAL = MCONTROL_MATCH_EQUAL,
  MATCH_NAPOT = MCONTROL_MATCH_NAPOT,
  MATCH_GE = MCONTROL_MATCH_GE,
  MATCH_LT = MCONTROL_MATCH_LT,
  MATCH_MASK_LOW = MCONTROL_MATCH_MASK_LOW,
  MATCH_MASK_HIGH = MCONTROL_MATCH_MASK_HIGH
} mcontrol_match_t;

typedef struct
{
  uint8_t type;
  bool dmode;
  uint8_t maskmax;
  bool select;
  bool timing;
  mcontrol_action_t action;
  bool chain;
  mcontrol_match_t match;
  bool m;
  bool h;
  bool s;
  bool u;
  bool execute;
  bool store;
  bool load;
} mcontrol_t;

enum VRM{
  RNU = 0,
  RNE,
  RDN,
  ROD,
  INVALID_RM
};

template<uint64_t N>
struct type_usew_t;

template<>
struct type_usew_t<8>
{
  using type=uint8_t;
};

template<>
struct type_usew_t<16>
{
  using type=uint16_t;
};

template<>
struct type_usew_t<32>
{
  using type=uint32_t;
};

template<>
struct type_usew_t<64>
{
  using type=uint64_t;
};

template<uint64_t N>
struct type_sew_t;

template<>
struct type_sew_t<8>
{
  using type=int8_t;
};

template<>
struct type_sew_t<16>
{
  using type=int16_t;
};

template<>
struct type_sew_t<32>
{
  using type=int32_t;
};

template<>
struct type_sew_t<64>
{
  using type=int64_t;
};


// architectural state of a RISC-V hart
struct state_t
{
  void reset(processor_t* const proc, reg_t max_isa, uint32_t id);

  static const int num_triggers = 4;

  reg_t pc;
  regfile_t<reg_t, NXPR, true> XPR;
  regfile_t<freg_t, NFPR, false> FPR;

  // control and status registers
  std::unordered_map<reg_t, csr_t_p> csrmap;
  reg_t prv;    // TODO: Can this be an enum instead?
  bool v;
  misa_csr_t_p misa;
  mstatus_csr_t_p mstatus;
  csr_t_p mepc;
  csr_t_p mtval;
  csr_t_p mtvec;
  csr_t_p mcause;
  reg_t minstret;
  mie_csr_t_p mie;
  mip_csr_t_p mip;
  csr_t_p medeleg;
  csr_t_p mideleg;
  csr_t_p mcounteren;
  csr_t_p scounteren;
  csr_t_p sepc;
  csr_t_p stval;
  csr_t_p stvec;
  virtualized_csr_t_p satp;
  csr_t_p scause;

  reg_t mtval2;
  reg_t mtinst;
  csr_t_p hstatus;
  reg_t hideleg;
  reg_t hedeleg;
  csr_t_p hcounteren;
  reg_t htval;
  reg_t htinst;
  reg_t hgatp;
  sstatus_csr_t_p sstatus;
  vsstatus_csr_t_p vsstatus;
  csr_t_p vstvec;
  csr_t_p vsepc;
  csr_t_p vscause;
  csr_t_p vstval;
  csr_t_p vsatp;

  reg_t dpc;
  reg_t dscratch0, dscratch1;
  dcsr_t dcsr;
  reg_t tselect;
  mcontrol_t mcontrol[num_triggers];
  reg_t tdata2[num_triggers];
  bool debug_mode;

  static const int max_pmp = 16;
  pmpaddr_csr_t_p pmpaddr[max_pmp];

  uint32_t fflags;
  uint32_t frm;
  bool serialized; // whether timer CSRs are in a well-defined state

  // When true, execute a single instruction and then enter debug mode.  This
  // can only be set by executing dret.
  enum {
      STEP_NONE,
      STEP_STEPPING,
      STEP_STEPPED
  } single_step;

#ifdef RISCV_ENABLE_COMMITLOG
  commit_log_reg_t log_reg_write;
  commit_log_mem_t log_mem_read;
  commit_log_mem_t log_mem_write;
  reg_t last_inst_priv;
  int last_inst_xlen;
  int last_inst_flen;
#endif

  size_t pid;

  state_t(size_t id): XPR(id), FPR(id), pid(id) {};
  state_t(): XPR(0), FPR(0), pid(0) {};
};

typedef enum {
  OPERATION_EXECUTE,
  OPERATION_STORE,
  OPERATION_LOAD,
} trigger_operation_t;

typedef enum {
  // 65('A') ~ 90('Z') is reserved for standard isa in misa
  EXT_ZFH,
  EXT_ZBA,
  EXT_ZBB,
  EXT_ZBC,
  EXT_ZBS,
  EXT_ZBKB,
  EXT_ZBKC,
  EXT_ZBKX,
  EXT_ZKND,
  EXT_ZKNE,
  EXT_ZKNH,
  EXT_ZKSED,
  EXT_ZKSH,
  EXT_ZKR,
  EXT_SVNAPOT,
  EXT_SVPBMT,
  EXT_SVINVAL,
  EXT_XBITMANIP,
} isa_extension_t;

typedef enum {
  IMPL_MMU_SV32,
  IMPL_MMU_SV39,
  IMPL_MMU_SV48,
  IMPL_MMU_SBARE,
  IMPL_MMU,
} impl_extension_t;

// Count number of contiguous 1 bits starting from the LSB.
static int cto(reg_t val)
{
  int res = 0;
  while ((val & 1) == 1)
    val >>= 1, res++;
  return res;
}

// this class represents one processor in a RISC-V machine.
class processor_t : public abstract_device_t
{
public:
  processor_t(const char* isa, const char* priv, const char* varch,
              simif_t* sim, uint32_t id, bool halt_on_reset,
              std::ostream& sout_); // because of command line option --log and -s we need both
  ~processor_t();

  bool set_pc_api(const std::string& name, const uint8_t* bytes, size_t len); //len advertises the size of the buffer
  bool retrieve_pc_api(uint8_t* bytes, const std::string& name, size_t len); //len advertises the size of the buffer

  void retrieve_privilege_api(reg_t* prv);

  void set_debug(bool value);
  void set_histogram(bool value);
#ifdef RISCV_ENABLE_COMMITLOG
  void enable_log_commits();
  bool get_log_commits_enabled() const { return log_commits_enabled; }
#endif
  void reset();
  void step(size_t n); // run for n cycles
  void set_csr(int which, reg_t val);
  void set_csr_api(int which, reg_t val);
  uint32_t get_id() const { return id; }
  reg_t get_csr(int which, insn_t insn, bool write, bool peek = 0);
  reg_t get_csr(int which) { return get_csr(which, insn_t(0), false, true); }
  reg_t get_csr_api(int which);
  mmu_t* get_mmu() { return mmu; }
  state_t* get_state() { return &state; }
  unsigned get_xlen() { return xlen; }
  unsigned get_const_xlen() {
    // Any code that assumes a const xlen should use this method to
    // document that assumption. If Spike ever changes to allow
    // variable xlen, this method should be removed.
    return xlen;
  }
  unsigned get_max_xlen() { return max_xlen; }
  std::string get_isa_string() { return isa_string; }
  unsigned get_flen() {
    return extension_enabled('Q') ? 128 :
           extension_enabled('D') ? 64 :
           extension_enabled('F') ? 32 : 0;
  }
  extension_t* get_extension();
  extension_t* get_extension(const char* name);
  bool any_custom_extensions() const {
    return !custom_extensions.empty();
  }
  bool extension_enabled(unsigned char ext) const {
    if (ext >= 'A' && ext <= 'Z')
      return state.misa->extension_enabled(ext);
    else
      return extension_table[ext];
  }
  // Is this extension enabled? and abort if this extension can
  // possibly be disabled dynamically. Useful for documenting
  // assumptions about writable misa bits.
  bool extension_enabled_const(unsigned char ext) const {
    if (ext >= 'A' && ext <= 'Z')
      return state.misa->extension_enabled_const(ext);
    else
      return extension_table[ext];  // assume this can't change
  }
  void set_impl(uint8_t impl, bool val) { impl_table[impl] = val; }
  bool supports_impl(uint8_t impl) const {
    return impl_table[impl];
  }
  reg_t pc_alignment_mask() {
    return ~(reg_t)(extension_enabled('C') ? 0 : 2);
  }
  void check_pc_alignment(reg_t pc) {
    if (unlikely(pc & ~pc_alignment_mask()))
      throw trap_instruction_address_misaligned(state.v, pc, 0, 0);
  }
  reg_t legalize_privilege(reg_t);
  void set_privilege(reg_t);
  void set_privilege_api(reg_t prv);
  void set_virt(bool);
  void update_histogram(reg_t pc);
  const disassembler_t* get_disassembler() { return disassembler; }

  FILE *get_log_file() { return log_file; }

  void register_insn(insn_desc_t);
  void register_extension(extension_t*);

  // MMIO slave interface
  bool load(reg_t addr, size_t len, uint8_t* bytes);
  bool store(reg_t addr, size_t len, const uint8_t* bytes);

  // When true, display disassembly of each instruction that's executed.
  bool debug;
  // When true, take the slow simulation path.
  bool slow_path();
  bool halted() { return state.debug_mode; }
  enum {
    HR_NONE,    /* Halt request is inactive. */
    HR_REGULAR, /* Regular halt request/debug interrupt. */
    HR_GROUP    /* Halt requested due to halt group. */
  } halt_request;

  // Return the index of a trigger that matched, or -1.
  inline int trigger_match(trigger_operation_t operation, reg_t address, reg_t data)
  {
    if (state.debug_mode)
      return -1;

    bool chain_ok = true;

    for (unsigned int i = 0; i < state.num_triggers; i++) {
      if (!chain_ok) {
        chain_ok |= !state.mcontrol[i].chain;
        continue;
      }

      if ((operation == OPERATION_EXECUTE && !state.mcontrol[i].execute) ||
          (operation == OPERATION_STORE && !state.mcontrol[i].store) ||
          (operation == OPERATION_LOAD && !state.mcontrol[i].load) ||
          (state.prv == PRV_M && !state.mcontrol[i].m) ||
          (state.prv == PRV_S && !state.mcontrol[i].s) ||
          (state.prv == PRV_U && !state.mcontrol[i].u)) {
        continue;
      }

      reg_t value;
      if (state.mcontrol[i].select) {
        value = data;
      } else {
        value = address;
      }

      // We need this because in 32-bit mode sometimes the PC bits get sign
      // extended.
      if (xlen == 32) {
        value &= 0xffffffff;
      }

      switch (state.mcontrol[i].match) {
        case MATCH_EQUAL:
          if (value != state.tdata2[i])
            continue;
          break;
        case MATCH_NAPOT:
          {
            reg_t mask = ~((1 << (cto(state.tdata2[i])+1)) - 1);
            if ((value & mask) != (state.tdata2[i] & mask))
              continue;
          }
          break;
        case MATCH_GE:
          if (value < state.tdata2[i])
            continue;
          break;
        case MATCH_LT:
          if (value >= state.tdata2[i])
            continue;
          break;
        case MATCH_MASK_LOW:
          {
            reg_t mask = state.tdata2[i] >> (xlen/2);
            if ((value & mask) != (state.tdata2[i] & mask))
              continue;
          }
          break;
        case MATCH_MASK_HIGH:
          {
            reg_t mask = state.tdata2[i] >> (xlen/2);
            if (((value >> (xlen/2)) & mask) != (state.tdata2[i] & mask))
              continue;
          }
          break;
      }

      if (!state.mcontrol[i].chain) {
        return i;
      }
      chain_ok = true;
    }
    return -1;
  }

  void trigger_updated();

  void set_pmp_num(reg_t pmp_num);
  void set_pmp_granularity(reg_t pmp_granularity);
  void set_mmu_capability(int cap);

  const char* get_symbol(uint64_t addr);

private:
  simif_t* sim;
  mmu_t* mmu; // main memory is always accessed via the mmu
  std::unordered_map<std::string, extension_t*> custom_extensions;
  disassembler_t* disassembler;
  state_t state;
  uint32_t id;
  unsigned max_xlen;
  unsigned xlen;
  reg_t max_isa;
  std::string isa_string;
  bool histogram_enabled;
  bool log_commits_enabled;
  FILE *log_file;
  std::ostream sout_; // needed for socket command interface -s, also used for -d and -l, but not for --log
  bool halt_on_reset;
  std::vector<bool> extension_table;
  std::vector<bool> impl_table;

  entropy_source es; // Crypto ISE Entropy source.

  std::vector<insn_desc_t> instructions;
  std::map<reg_t,uint64_t> pc_histogram;

  static const size_t OPCODE_CACHE_SIZE = 8191;
  insn_desc_t opcode_cache[OPCODE_CACHE_SIZE];

  void take_pending_interrupt() { take_interrupt(state.mip->read() & state.mie->read()); }
  void take_interrupt(reg_t mask); // take first enabled interrupt in mask
  void take_trap(trap_t& t, reg_t epc); // take an exception
  void disasm(insn_t insn); // disassemble and print an instruction
  int paddr_bits();

  void enter_debug_mode(uint8_t cause);

  void debug_output_log(std::stringstream *s); // either output to interactive user or write to log file

  friend class mmu_t;
  friend class clint_t;
  friend class extension_t;

  void parse_varch_string(const char*);
  void parse_priv_string(const char*);
  void parse_isa_string(const char*);
  void build_opcode_map();
  void register_base_instructions();
  insn_func_t decode_insn(insn_t insn);

  // Track repeated executions for processor_t::disasm()
  uint64_t last_pc, last_bits, executions;
public:
  reg_t n_pmp;
  reg_t lg_pmp_granularity;
  reg_t pmp_tor_mask() { return -(reg_t(1) << (lg_pmp_granularity - PMP_SHIFT)); }

  class vectorUnit_t {
    public:
      processor_t* p;
      void *reg_file;
      char reg_referenced[NVPR];
      int setvl_count;
      reg_t vlmax;
      reg_t vstart, vxrm, vxsat, vl, vtype, vlenb;
      reg_t vma, vta;
      reg_t vsew;
      float vflmul;
      reg_t ELEN, VLEN;
      bool vill;
      bool vstart_alu;

      template<class T>
      void do_callback(reg_t vecRegIndex, reg_t eltIndex, const char pAccessType[]) const; 
  
      // vector element for varing SEW
      template<class T>
        T& elt(reg_t vReg, reg_t n, bool is_write = false){
          assert(vsew != 0);
          assert((VLEN >> 3)/sizeof(T) > 0);
          reg_t elts_per_reg = (VLEN >> 3) / (sizeof(T));
          vReg += n / elts_per_reg;
          n = n % elts_per_reg;
          reg_referenced[vReg] = 1;
  
#ifdef WORDS_BIGENDIAN
          // "V" spec 0.7.1 requires lower indices to map to lower significant
          // bits when changing SEW, thus we need to index from the end on BE.
          n ^= elts_per_reg - 1;
#endif

          T *regStart = (T*)((char*)reg_file + vReg * (VLEN >> 3));
          return regStart[n];
        }
  
      template<class T>
        T elt_val(reg_t vecReg, reg_t n, bool is_write = false){
          T reg_val = elt<T>(vecReg, n, is_write);
          do_callback<T>(vecReg, n, "read"); 
          return reg_val;
        }
  
       template<class T>
        T& elt_ref(reg_t vecReg, reg_t n, bool is_write = false){
          T& r_reg_ref = elt<T>(vecReg, n, is_write);
          do_callback<T>(vecReg, n, "write"); 
          return r_reg_ref;
        }

    public:

      void reset();

      vectorUnit_t(){
        reg_file = 0;
      }

      ~vectorUnit_t(){
        free(reg_file);
        reg_file = 0;
      }

      reg_t set_vl(int rd, int rs1, reg_t reqVL, reg_t newType);
      reg_t set_vl_api(reg_t reqVL, reg_t newType);

      reg_t get_vlen() { return VLEN; }
      reg_t get_elen() { return ELEN; }
      reg_t get_slen() { return VLEN; }

      VRM get_vround_mode() {
        return (VRM)vxrm;
      }
  };

  vectorUnit_t VU;
};

extern "C"{
  // update_vector_element function: for the given cpuid, this callback function is called by the simulator to notify the user that a vector register element has been read or written
  //
  //  inputs:
  //      uint32_t cpuid -- refers to the processor ID
  //      const char* pRegName -- the base name of the vector register does NOT include a suffix for physical register since this is a FORCE / hardware specific notion.
  //      uint32_t vecRegIndex -- the numerical index that goes with the vector register base name
  //      uint32_t eltIndex -- the numerical index of the element that is updated
  //      uint32_t eltByteWidth -- the number of bytes per element at the time of the update, used in FORCE with the eltIndex to dynamically associate physical registers for aggregated updates
  //      const uint8_t* value -- the contents of the ENTIRE vector register if this update is a "read" or *nothing* if this is a "write". 
  //      uint32_t byteLength -- should match the size of the ENTIRE vector register.
  //      const char* pAccessType -- should be "read" or "write".
  //
  void update_vector_element(uint32_t cpuid, const char *pRegName, uint32_t vecRegIndex, uint32_t eltIndex, uint32_t eltByteWidth, const uint8_t* pValue, uint32_t  byteLength, const char* pAccessType);
}

extern const char* vr_name[];

template<class T>
void processor_t::vectorUnit_t::do_callback(reg_t vecRegIndex, reg_t eltIndex, const char pAccessType[]) const  
{
  reg_t elts_per_reg = (VLEN >> 3) / (sizeof(T));
  reg_t corrected_vreg_index = vecRegIndex + eltIndex / elts_per_reg;
  if(corrected_vreg_index > vecRegIndex)
  {
    eltIndex %= elts_per_reg;  	
  }

  #ifdef WORDS_BIGENDIAN
  // "V" spec 0.7.1 requires lower indices to map to lower significant
  // bits when changing SEW, thus we need to index from the end on BE.
  eltIndex ^= elts_per_reg - 1;
  #endif

  uint8_t *p_reg_start = (uint8_t*)((char*)reg_file + corrected_vreg_index * (VLEN >> 3));
  update_vector_element(p->get_state()->pid, vr_name[corrected_vreg_index], corrected_vreg_index, eltIndex, sizeof(T), p_reg_start, (VLEN >> 3), pAccessType);
}

reg_t illegal_instruction(processor_t* p, insn_t insn, reg_t pc);

#define REGISTER_INSN(proc, name, match, mask, archen) \
  extern reg_t rv32_##name(processor_t*, insn_t, reg_t); \
  extern reg_t rv64_##name(processor_t*, insn_t, reg_t); \
  proc->register_insn((insn_desc_t){match, mask, rv32_##name, rv64_##name,archen});

#endif
