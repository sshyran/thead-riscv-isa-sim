// vfcvt.x.f.v vd, vd2, vm
VI_VFP_VF_LOOP
({
  P.VU.elt_ref<int16_t>(rd_num, i) = f16_to_i16(vs2, STATE.frm, true);
},
{
  P.VU.elt_ref<int32_t>(rd_num, i) = f32_to_i32(vs2, STATE.frm, true);
},
{
  P.VU.elt_ref<int64_t>(rd_num, i) = f64_to_i64(vs2, STATE.frm, true);
})
