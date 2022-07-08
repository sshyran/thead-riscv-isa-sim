// vfncvt.rtz.x.f.w vd, vs2, vm
VI_VFP_CVT_SCALE
({
  auto vs2 = P.VU.elt_val<float16_t>(rs2_num, i);
  P.VU.elt_ref<int8_t>(rd_num, i, true) = f16_to_i8(vs2, softfloat_round_minMag, true);
},
{
  auto vs2 = P.VU.elt_val<float32_t>(rs2_num, i);
  P.VU.elt_ref<int16_t>(rd_num, i, true) = f32_to_i16(vs2, softfloat_round_minMag, true);
},
{
  auto vs2 = P.VU.elt_val<float64_t>(rs2_num, i);
  P.VU.elt_ref<int32_t>(rd_num, i, true) = f64_to_i32(vs2, softfloat_round_minMag, true);
},
{
  require(p->extension_enabled(EXT_ZFH));
},
{
  require(p->extension_enabled('F'));
},
{
  require(p->extension_enabled('D'));
},
false, (P.VU.vsew <= 32))
