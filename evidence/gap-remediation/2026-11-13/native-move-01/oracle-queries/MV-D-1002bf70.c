
uint FUN_1002bf70(short *param_1,uint param_2,byte *param_3)

{
  undefined4 uVar1;
  short sVar2;
  char local_e0 [8];
  byte local_d8;
  undefined1 auStack_d7 [63];
  undefined1 auStack_98 [18];
  byte *local_86;
  short local_82;
  undefined2 local_7c;
  undefined4 local_68;
  
  if (param_1 == (short *)0x0) {
    FUN_10027c30(1,2);
  }
  uVar1 = FUN_1002e1b0((int)*param_1,*(undefined4 *)(param_1 + 1),param_1 + 3,local_e0);
  if (local_e0[0] == '\0') {
    FUN_10027c30(4,0x7d);
  }
  local_7c = 0;
  local_82 = *param_1;
  local_86 = &local_d8;
  if (0x1c < *param_3) {
    *param_3 = 0x1c;
  }
  do {
    local_d8 = FUN_10054180(auStack_d7,0x1f,0x10093c56,param_3,param_2 & 0xffff);
    param_2 = param_2 + 1;
    local_68 = uVar1;
    sVar2 = .glue::PBGetCatInfoSync(auStack_98);
  } while (sVar2 == 0);
  .glue::BlockMoveData(&local_d8,param_3,local_d8 + 1);
  return param_2;
}

