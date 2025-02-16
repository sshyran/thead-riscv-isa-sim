// vsbc.vvm vd, vs2, rs1, v0
VI_VV_LOOP_WITH_CARRY
({
  auto &v0 = P.VU.elt_ref<uint64_t>(0, midx);
  const uint128_t op_mask = (UINT64_MAX >> (64 - sew));
  uint64_t carry = (v0 >> mpos) & 0x1;

  uint128_t res = (op_mask & vs2) - (op_mask & vs1) - carry;
  vd = res;
})
