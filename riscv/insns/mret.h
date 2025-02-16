require_privilege(PRV_M);
set_pc_and_serialize(p->get_state()->mepc->read());
reg_t s = STATE.mstatus->read();
SimException exit_m(0x4e, 0, "exit_mret", p->get_state()->mepc->read());
update_exception_event(&exit_m); 
reg_t prev_prv = get_field(s, MSTATUS_MPP);
reg_t prev_virt = get_field(s, MSTATUS_MPV);
if (prev_prv != PRV_M)
  s = set_field(s, MSTATUS_MPRV, 0);
s = set_field(s, MSTATUS_MIE, get_field(s, MSTATUS_MPIE));
s = set_field(s, MSTATUS_MPIE, 1);
s = set_field(s, MSTATUS_MPP, PRV_U);
p->set_csr(CSR_MSTATUS, s);
p->set_privilege(prev_prv);
p->set_virt(prev_virt);
