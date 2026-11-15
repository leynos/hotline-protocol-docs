
undefined4 FUN_1002f600(undefined2 *param_1,undefined2 *param_2,ushort *param_3)

{
  ushort uVar1;
  short sVar3;
  undefined4 uVar2;
  char local_110;
  char local_10f;
  char local_10e [6];
  undefined1 local_108 [64];
  undefined2 local_c8;
  undefined4 local_c6;
  undefined8 local_c2;
  undefined8 local_ba;
  undefined8 local_b2;
  undefined8 local_aa;
  undefined8 local_a2;
  undefined8 local_9a;
  undefined8 local_92;
  undefined8 local_8a;
  undefined1 auStack_80 [18];
  undefined1 *local_6e;
  undefined2 local_6a;
  undefined1 local_66;
  undefined2 local_64;
  undefined4 local_50;
  
  local_c8 = *param_1;
  local_c6 = *(undefined4 *)(param_1 + 1);
  local_c2 = *(undefined8 *)(param_1 + 3);
  local_ba = *(undefined8 *)(param_1 + 7);
  local_b2 = *(undefined8 *)(param_1 + 0xb);
  local_aa = *(undefined8 *)(param_1 + 0xf);
  local_a2 = *(undefined8 *)(param_1 + 0x13);
  local_9a = *(undefined8 *)(param_1 + 0x17);
  local_92 = *(undefined8 *)(param_1 + 0x1b);
  local_8a = *(undefined8 *)(param_1 + 0x1f);
  *param_2 = local_c8;
  *(undefined4 *)(param_2 + 1) = local_c6;
  *(undefined8 *)(param_2 + 3) = local_c2;
  *(undefined8 *)(param_2 + 7) = local_ba;
  *(undefined8 *)(param_2 + 0xb) = local_b2;
  *(undefined8 *)(param_2 + 0xf) = local_aa;
  *(undefined8 *)(param_2 + 0x13) = local_a2;
  *(undefined8 *)(param_2 + 0x17) = local_9a;
  *(undefined8 *)(param_2 + 0x1b) = local_92;
  *(undefined8 *)(param_2 + 0x1f) = local_8a;
  if (DAT_10093be9 == '\0') {
    sVar3 = FUN_1002f310(param_2,1,&local_110,&local_10f,0);
  }
  else {
    sVar3 = .glue::ResolveAliasFile(param_2,1,&local_110,&local_10f);
  }
  if (sVar3 == 0) {
    if (param_3 != (ushort *)0x0) {
      if (local_110 == '\0') {
        uVar1 = 2;
        if (local_10f != '\0') {
          uVar1 = 4;
        }
        *param_3 = uVar1;
      }
      else {
        uVar1 = 3;
        if (local_10f != '\0') {
          uVar1 = 5;
        }
        *param_3 = uVar1;
      }
    }
    uVar2 = 1;
  }
  else {
    if (param_3 != (ushort *)0x0) {
      FUN_1002f210(&local_c8,local_10e,&local_110);
      if (local_10e[0] == '\0') {
        local_108[0] = 0;
        local_6e = local_108;
        local_6a = local_c8;
        local_50 = local_c6;
        local_66 = 0;
        local_64 = 0xffff;
        sVar3 = .glue::PBGetCatInfoSync(auStack_80);
        *param_3 = (ushort)(-(uint)(sVar3 == 0) >> 0x1f);
      }
      else {
        *param_3 = 6;
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

