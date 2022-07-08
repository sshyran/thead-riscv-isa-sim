// vmv1r.v vd, vs2
require_vector_novtype(true, true);
const reg_t baseAddr = RS1;
const reg_t vd = insn.rd();
const reg_t vs2 = insn.rs2();
const reg_t len = insn.rs1() + 1;
require_align(vd, len);
require_align(vs2, len);
const reg_t size = len * P.VU.vlenb;

//register needs one-by-one copy to keep commitlog correct
if (vd != vs2 && P.VU.vstart < size) {
  reg_t i = P.VU.vstart / P.VU.vlenb;
  reg_t off = P.VU.vstart % P.VU.vlenb;

  // Commented out the original memcpy implementations. We need the instrumented elt() calls to
  // trigger the vector state update callbacks.
  if (off) {
    //memcpy(&P.VU.elt<uint8_t>(vd + i, off, true),
    //       &P.VU.elt<uint8_t>(vs2 + i, off), P.VU.vlenb - off);
    for(reg_t _byte = off; _byte < (P.VU.vlenb - off); ++_byte) {
      P.VU.elt_ref<uint8_t>(vd + i, _byte, true) = P.VU.elt_val<uint8_t>(vs2 + i, _byte);
    }

    i++;
  }

  for (; i < len; ++i) {
    //memcpy(&P.VU.elt<uint8_t>(vd + i, 0, true),
    //       &P.VU.elt<uint8_t>(vs2 + i, 0), P.VU.vlenb);
    for(reg_t _byte = 0; _byte < P.VU.vlenb; ++_byte) {
      P.VU.elt_ref<uint8_t>(vd + i, _byte, true) = P.VU.elt_val<uint8_t>(vs2 + i, _byte);
    }
  }
}

P.VU.vstart = 0;
