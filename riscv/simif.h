// See LICENSE for license details.

#ifndef _RISCV_SIMIF_H
#define _RISCV_SIMIF_H

#include "decode.h"
#include "Force_Memory.h"

// this is the interface to the simulator used by the processors and memory
class simif_t
{
public:
  virtual ~simif_t() = default;
  virtual void proc_reset(unsigned id) = 0;

  // to support sparse memory model
  virtual uint64_t sparse_read(reg_t paddr, size_t len) = 0;
  virtual void sparse_read_partially_initialized(reg_t paddr, size_t len, uint8_t* bytes) = 0;
  virtual void sparse_write(reg_t paddr, const uint8_t* bytes, size_t len) = 0;
  virtual void sparse_write(reg_t paddr, uint64_t value, size_t len) = 0;
  virtual void sparse_write_with_initialization(reg_t paddr, const uint8_t* bytes, size_t len) = 0;
  virtual bool sparse_is_pa_initialized(reg_t paddr, size_t len) = 0;
  virtual void sparse_initialize_pa(reg_t paddr, reg_t value, size_t numBytes, Force::EMemDataType type) = 0;
  virtual void sparse_initialize_pa(reg_t paddr, const uint8_t* data, const uint8_t* attrs, uint32_t nBytes, Force::EMemDataType type) = 0;
  virtual void sparse_reserve(reg_t paddr, size_t numBytes) = 0;
  virtual void sparse_unreserve(reg_t paddr, size_t numBytes) = 0;
  virtual bool sparse_is_reserved(reg_t paddr, size_t numBytes) = 0;
};

#endif
