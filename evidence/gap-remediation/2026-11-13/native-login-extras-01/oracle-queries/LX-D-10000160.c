
undefined4 * FUN_10000160(undefined4 *param_1)

{
  undefined1 auStack_100 [128];
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined1 *local_14;
  
  FUN_10028230();
  *param_1 = &PTR_PTR_1008f838;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  FUN_10055460(param_1 + 0xe);
  FUN_10055460(param_1 + 0x11);
  FUN_10055460(param_1 + 0x14);
  FUN_10055460(param_1 + 0x17);
  FUN_10055460(param_1 + 0x1a);
  FUN_10055460(param_1 + 0x1d);
  FUN_10055460(param_1 + 0x20);
  param_1[0x108] = 0;
  FUN_10055460(param_1 + 0x10f);
  FUN_10055460(param_1 + 0x112);
  local_40 = *(undefined8 *)PTR_DAT_10089160;
  local_38 = *(undefined8 *)(PTR_DAT_10089160 + 8);
  local_30 = *(undefined8 *)(PTR_DAT_10089160 + 0x10);
  *(undefined1 *)(param_1 + 0x2ab) = 0;
  *(byte *)(param_1 + 0x32) = *(byte *)(param_1 + 0x32) & 0xbf;
  local_14 = auStack_100 + 0x80;
  FUN_10057870();
  FUN_1006cd50(param_1 + 0x27,0x14);
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[0xb] = 0;
  param_1[0x30] = 0;
  *(undefined2 *)((int)param_1 + 0xbe) = 0;
  *(undefined2 *)(param_1 + 0x2f) = 0;
  *(undefined2 *)(param_1 + 0x31) = 0;
  param_1[0x24] = 0;
  param_1[0x23] = 0;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  *(byte *)(param_1 + 0x32) = *(byte *)(param_1 + 0x32) & 0x7f;
  FUN_1006cd50(param_1 + 0x10a,0x14);
  *(undefined2 *)(param_1 + 0x103) = 0;
  *(undefined1 *)(param_1 + 0x109) = 0;
  param_1[0x107] = 0;
  param_1[0x2e] = 0;
  param_1[0x2d] = 0;
  param_1[0x2c] = 0;
  param_1[0x106] = 0;
  param_1[0x105] = 0;
  param_1[0x104] = 0;
  FUN_1003b300(&local_40,3,PTR_PTR_10088d98,param_1);
  return param_1;
}

