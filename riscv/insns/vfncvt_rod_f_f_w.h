// vfncvt.rod.f.f.v vd, vs2, vm
VI_VFP_CVT_SCALE
({
  ;
},
{
  softfloat_roundingMode = softfloat_round_odd;
  auto vs2 = P.VU.elt_val<float32_t>(rs2_num, i);
  P.VU.elt_ref<float16_t>(rd_num, i, true) = f32_to_f16(vs2);
},
{
  softfloat_roundingMode = softfloat_round_odd;
  auto vs2 = P.VU.elt_val<float64_t>(rs2_num, i);
  P.VU.elt_ref<float32_t>(rd_num, i, true) = f64_to_f32(vs2);
},
{
  ;
},
{
  require(p->extension_enabled(EXT_ZFH));
},
{
  require(p->extension_enabled('F'));
},
false, (P.VU.vsew >= 16))
