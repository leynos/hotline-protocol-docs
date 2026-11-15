
undefined4 FUN_1002cb20(short *param_1,uint param_2)

{
  undefined4 uVar1;
  undefined2 uVar4;
  undefined4 uVar2;
  undefined4 uVar3;
  short sVar5;
  ushort uVar6;
  char local_1e0;
  undefined1 uStack_1df;
  undefined1 auStack_1de [2];
  undefined1 auStack_1dc [18];
  byte *local_1ca;
  undefined2 local_1c6;
  ushort local_1c0;
  byte local_1be;
  undefined4 local_1bc;
  undefined4 local_1b8;
  ushort local_1b4;
  undefined4 local_1ac;
  ushort local_1a8;
  int local_1a6;
  int local_19c;
  undefined4 local_194;
  undefined4 local_190;
  undefined4 local_178;
  undefined2 local_170;
  undefined4 local_16e;
  byte local_16a [66];
  undefined4 local_128;
  undefined4 local_124;
  uint local_120;
  uint local_11c;
  undefined4 local_118;
  undefined2 local_114;
  undefined2 local_112;
  undefined4 local_110;
  undefined2 local_10c;
  undefined2 local_10a;
  undefined4 local_108;
  byte local_104 [232];
  
  if (param_1 == (short *)0x0) {
    FUN_10027c30(1,2);
  }
  uVar6 = 1;
  uVar1 = FUN_1002e1b0((int)*param_1,*(undefined4 *)(param_1 + 1),param_1 + 3,&local_1e0);
  if (local_1e0 == '\0') {
    FUN_10027c30(4,0x7d);
  }
  uVar4 = FUN_1002e270(param_1 + 3,(int)*param_1);
  uVar2 = FUN_10052c50(4,0);
  local_10c = 0x770;
  local_114 = 0x770;
  local_10a = 0;
  local_112 = 0;
  local_118 = 0;
  while( true ) {
    local_1ca = local_104;
    local_1c6 = uVar4;
    local_1c0 = uVar6;
    local_1ac = uVar1;
    uVar3 = .glue::PBGetCatInfoSync(auStack_1dc);
    if ((short)uVar3 != 0) break;
    if ((local_1be & 0x10) == 0) {
      local_11c = local_1b4 >> 0xe & 1;
      if ((local_1b4 & 0x8000) != 0) {
        local_11c = local_11c | 2;
        local_170 = local_1c6;
        local_16e = local_178;
        .glue::BlockMoveData(local_104,local_16a,local_104[0] + 1);
        if (((param_2 & 1) == 0) &&
           (sVar5 = FUN_1002f5a0(&local_170,&uStack_1df,auStack_1de), sVar5 == 0)) {
          local_1ca = local_16a;
          local_1ac = local_16e;
          local_1c6 = local_170;
          local_1c0 = -(ushort)(local_16a[0] == 0);
          sVar5 = .glue::PBGetCatInfoSync(auStack_1dc);
          if (sVar5 == 0) {
            if ((local_1be & 0x10) != 0) goto LAB_1002cc14;
            goto LAB_1002cd1c;
          }
        }
        local_1bc = 0x616c6973;
        local_1b8 = 0;
        local_19c = 0;
        local_1a6 = 0;
      }
LAB_1002cd1c:
      local_128 = local_1bc;
      local_124 = local_1b8;
      local_120 = local_1a6 + local_19c;
    }
    else {
LAB_1002cc14:
      local_128 = 0x666c6472;
      local_124 = 0;
      local_120 = (uint)local_1a8;
      local_11c = local_1b4 >> 0xe & 1;
    }
    local_110 = local_194;
    local_108 = local_190;
    uVar3 = .glue::PtrAndHand(&local_128,uVar2,local_104[0] + 0x28 & 0xfffffffc);
    if ((short)uVar3 != 0) goto LAB_1002cdbc;
    uVar6 = uVar6 + 1;
  }
  if ((short)uVar3 == -0x2b) {
    if (uVar6 == 1) {
      FUN_10052e90(uVar2);
      uVar2 = 0;
    }
    else {
      FUN_10053890(uVar2,0,uVar6 - 1);
    }
  }
  else {
LAB_1002cdbc:
    FUN_10052e90(uVar2);
    FUN_10028190(uVar3,0,0);
    uVar2 = 0;
  }
  return uVar2;
}

