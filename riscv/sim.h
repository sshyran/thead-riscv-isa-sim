// See LICENSE for license details.

#ifndef _RISCV_SIM_H
#define _RISCV_SIM_H

#include "Force_Memory.h"
#include "Force_Enums.h"

#include "config.h"

#include "processor.h"
#include "devices.h"
#include "simif.h"
#include <fesvr/memif.h>
#include <vector>
#include <string>
#include <memory>
#include <sys/types.h>

class mmu_t;
class remote_bitbang_t;

// this class encapsulates the processors and memory in a RISC-V machine.
class simlib_t : public simif_t
{
public:
  simlib_t(const char* isa, const char* priv, const char* varch, size_t _nprocs, bool halted,
        const char* bootargs, reg_t start_pc, const std::vector<int> hartids, bool auto_init_mem,
        FILE *cmd_file); // needed for command line option --cmd
  ~simlib_t();

  // load the elf file and reset
  int load_program_now(const char* elfPath);

  // run the simulation incrementally
  int step_simulator(int target_id, int num_steps, int stx_failed);

  // fetch the instruction at the given pc using the debug_mmu and return the opcode and disassembly
  int get_disassembly(int target_id, const uint64_t* pc, char** opcode, char** disassembly);

  // run the simulation to completion
  int run();
  void set_debug(bool value);
  void set_log(bool value);
  void set_histogram(bool value);

  // Configure logging
  //
  // If enable_log is true, an instruction trace will be generated. If
  // enable_commitlog is true, so will the commit results (if this
  // build was configured without support for commit logging, the
  // function will print an error message and abort).
  void configure_log(bool enable_log, bool enable_commitlog);

  void set_procs_debug(bool value);
  void set_dtb_enabled(bool value) {
    this->dtb_enabled = value;
  }
  void set_remote_bitbang(remote_bitbang_t* remote_bitbang) {
    this->remote_bitbang = remote_bitbang;
  }

  const char* get_dts() { if (dts.empty()) reset(); return dts.c_str(); }

  processor_t* get_core(size_t i) 
  { 
    for(processor_t* proc_ptr : procs)
    {
      if(proc_ptr != nullptr && proc_ptr->get_state() != nullptr && proc_ptr->get_state()->pid == i)
        return proc_ptr; 
    }

    return nullptr;
  }

  unsigned nprocs() const { return procs.size(); }

  bool doesCoreWithIdExist(size_t i);

  // for debugging the sparse memory model
  void dump_sparse_memory(std::ostream & out);

  // Callback for processors to let the simulation know they were reset.
  void proc_reset(unsigned id);

  //
  reg_t get_entry_point(){ return entry; };

  uint64_t get_csr_number(const std::string& input_name);
  uint64_t get_xpr_number(const std::string& input_name);
  uint64_t get_fpr_number(const std::string& input_name); 
  uint64_t get_vecr_number(const std::string& input_name);

  std::string get_csr_name(uint64_t index);
  std::string get_xpr_name(uint64_t index);
  std::string get_fpr_name(uint64_t index); 
  std::string get_vecr_name(uint64_t index);

  int read_csr(uint32_t procid, const std::string& input_name, uint64_t* value, uint32_t* length);
  int read_csr(uint32_t procid, uint64_t index, uint64_t* value, uint32_t* length);

  int read_xpr(uint32_t procid, const std::string& input_name, uint64_t* value, uint32_t* length);
  int read_xpr(uint32_t procid, uint64_t index, uint64_t* value, uint32_t* length);

  int read_fpr(uint32_t procid, const std::string& input_name, uint8_t* value, uint32_t* length);
  int read_fpr(uint32_t procid, uint64_t index, uint8_t* value, uint32_t* length);

  int read_vecr(uint32_t procid, const std::string& input_name, uint8_t* value, uint32_t* length);
  int read_vecr(uint32_t procid, uint64_t index, uint8_t* value, uint32_t* length);
  int partial_read_vecr(uint32_t procid, uint64_t index, uint8_t* pValue, uint32_t length, uint32_t offset);

  int write_csr(uint32_t procid, const std::string& input_name, const uint64_t* value, uint32_t length);
  int write_csr(uint32_t procid, uint64_t index, const uint64_t* value, uint32_t length);

  int write_xpr(uint32_t procid, const std::string& input_name, const uint64_t* value, uint32_t length);
  int write_xpr(uint32_t procid, uint64_t index, const uint64_t* value, uint32_t length);

  int write_fpr(uint32_t procid, const std::string& input_name, const uint8_t* value, uint32_t length);
  int write_fpr(uint32_t procid, uint64_t index, const uint8_t* value, uint32_t length);

  int write_vecr(uint32_t procid, const std::string& input_name, const uint8_t* value, uint32_t length);
  int write_vecr(uint32_t procid, uint64_t index, const uint8_t* value, uint32_t length);
  int partial_write_vecr(uint32_t procid, uint64_t index, const uint8_t* pValue, uint32_t length, uint32_t offset);

  void sparse_read_partially_initialized(reg_t paddr, size_t len, uint8_t* bytes);
  void sparse_write(reg_t paddr, const uint8_t* bytes, size_t len);
  void sparse_write_with_initialization(reg_t paddr, const uint8_t* bytes, size_t len);
  void sparse_write_multiword(reg_t paddr, const uint8_t* bytes, size_t len){};
  void sparse_initialize_pa(reg_t paddr, reg_t value, size_t numBytes);
  bool sparse_is_pa_initialized(reg_t paddr, size_t len);
  void sparse_reserve(reg_t paddr, size_t numBytes) override;
  void sparse_unreserve(reg_t paddr, size_t numBytes) override;
  bool sparse_is_reserved(reg_t paddr, size_t numBytes) override;
  void initialize_multiword(reg_t taddr, size_t len, const void* src); // To support multiword initializations during elf loading

  bool set_pc_api(int procid, const std::string& name, const uint8_t* bytes, size_t len);
  bool get_pc_api(int procid, uint8_t* bytes, const std::string& name, size_t len);

  bool set_privilege_api(int procid, const uint64_t* val);
  bool get_privilege_api(int procid, uint64_t* val);

  // translate_virtual_address_api function: attempts to translate a virtual address into a physical address, returns any error information and also gathers the relevant pmp address and pmp configuration.
  //
  //  meaning of 'intent':
  //    0 - indicates a 'LOAD' access
  //    1 - indicates a 'STORE' access
  //    2 - indicates a 'FETCH' access
  //
  //  returns:
  //    0 - success
  //    1 - some pointer arguments were null
  //    2 - invalid procid
  //    3 - PMP problem with PA after address translation somehow
  //    4 - access exception while trying to check pmp status of page table entry PA
  //    5 - walk was unsuccessful and access type was FETCH
  //    6 - walk was unsuccessful and access type was LOAD
  //    7 - walk was unsuccessful and access type was STORE
  //    8 - walk was unsuccessful and access type was not any of the above
  //
  int translate_virtual_address_api(int procid, const uint64_t* vaddr, int intent, uint64_t* paddr, uint64_t* memattrs);

private:
  mmu_t* debug_mmu;  // debug port into main memory
  std::vector<processor_t*> procs;
  reg_t initrd_start;
  reg_t initrd_end;
  const char* bootargs;
  reg_t start_pc;
  std::string dts;

  FILE *cmd_file; // pointer to debug command input file

  std::ostream sout_; // used for socket and terminal interface

  processor_t* get_core(const std::string& i);
  void step(size_t n); // step through simulation
  static const size_t INTERLEAVE = 5000;
  static const size_t INSNS_PER_RTC_TICK = 100; // 10 MHz clock for 1 BIPS core
  static const size_t CPU_HZ = 1000000000; // 1GHz CPU
  size_t current_step;
  size_t current_proc;
  bool debug;
  bool histogram_enabled; // provide a histogram of PCs
  bool log;
  bool dtb_enabled;
  remote_bitbang_t* remote_bitbang;

  void make_dtb();
  void set_rom();

  // sparse memory routines
  Force::Memory _ForceSparseMemoryModel;
  uint64_t sparse_read(reg_t paddr, size_t len);
  void sparse_write(reg_t paddr, uint64_t value, size_t len);
  //bool sparse_is_pa_initialized(reg_t paddr, size_t len);
  void sparse_initialize_pa(reg_t paddr, const uint8_t* data, const uint8_t* attrs, uint32_t nBytes, Force::EMemDataType type);
  void sparse_initialize_pa(reg_t paddr, reg_t value, size_t numBytes, Force::EMemDataType type);
  //void sparse_read_partially_initialized(reg_t paddr, size_t len, uint8_t* bytes);
  //void sparse_write(reg_t paddr, const uint8_t* bytes, size_t len);


  reg_t entry;
  std::map<std::string, uint64_t> load_elf(const char* fn, reg_t* entry);

  reg_t get_mem(const std::vector<std::string>& args);
  reg_t get_pc(const std::vector<std::string>& args);
    
  friend class processor_t;
  friend class mmu_t;
  friend class debug_module_t;

  // htif
  friend void sim_thread_main(void*);
  void main();

  void reset();
  //void idle();
  void read_chunk_partially_initialized(reg_t taddr, size_t len, void* dst);
  void clear_chunk(reg_t taddr, size_t len);
  //void initialize_multiword(reg_t taddr, size_t len, const void* src); // To support multiword initializations during elf loading
  void write_chunk(reg_t taddr, size_t len, const void* src);
  size_t chunk_align() { return 8; }
  size_t chunk_max_size() { return 8; }
  void set_target_endianness(memif_endianness_t endianness);
  memif_endianness_t get_target_endianness() const;

};

extern volatile bool ctrlc_pressed;

#endif
