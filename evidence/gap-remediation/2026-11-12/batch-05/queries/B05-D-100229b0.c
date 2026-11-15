
uint FUN_100229b0(int param_1,uint param_2,byte *param_3,byte *param_4,undefined4 param_5,
                 undefined2 *param_6,byte *param_7)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined1 uVar7;
  int iVar6;
  byte bVar8;
  int iVar9;
  undefined1 auStack_330 [128];
  int local_268;
  int local_264;
  undefined4 local_260 [7];
  undefined1 *local_244;
  int local_240;
  int local_23c;
  int local_228;
  uint local_220;
  int local_21c;
  uint local_218;
  int local_214;
  int local_210;
  int local_20c;
  uint local_208;
  undefined1 auStack_204 [12];
  int local_1f8;
  uint local_1f4;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002c220(param_1,0x23);
  iVar3 = FUN_1002c3b0(param_1,0,&local_240,0x17c,0);
  if (iVar3 != 0x17c) {
    FUN_10027c30(1,9);
  }
  if (local_240 != 0x484c4e5a) {
    FUN_10027c30(1,8);
  }
  if (local_23c != 2) {
    FUN_10027c30(1,7);
  }
  iVar3 = (local_1f4 + 1) * 8;
  iVar9 = local_220 * (local_1f8 + -1) + 0x200;
  iVar4 = FUN_10052a10(iVar3);
  FUN_1002c3b0(param_1,iVar9,iVar4,iVar3,0);
  iVar3 = 0;
  if (param_2 != 0) {
    iVar3 = FUN_10024280(param_1,local_220,param_2,iVar4 + (param_2 & local_1f4) * 8);
  }
  iVar5 = FUN_10023de0(param_1,local_220,auStack_204,1);
  uVar2 = local_208;
  local_268 = iVar5;
  local_244 = auStack_330 + 0x80;
  local_264 = FUN_10052a10(local_220);
  FUN_1006cd50(local_264,local_220);
  iVar1 = local_264;
  *(undefined4 *)(local_264 + 4) = 0xc0;
  FUN_1007c240(local_264 + 8,PTR_DAT_10089198);
  *(uint *)(iVar1 + 0x24) = local_208;
  *(int *)(iVar1 + 0x30) = iVar3;
  if (param_6 == (undefined2 *)0x0) {
    FUN_10057de0(iVar1 + 0x38);
  }
  else {
    *(undefined2 *)(iVar1 + 0x38) = *param_6;
    *(undefined2 *)(iVar1 + 0x3a) = param_6[1];
    *(undefined4 *)(iVar1 + 0x3c) = *(undefined4 *)(param_6 + 2);
  }
  *(undefined4 *)(iVar1 + 0x40) = param_5;
  bVar8 = 0x3f;
  if (*param_3 < 0x40) {
    bVar8 = *param_3;
  }
  uVar7 = FUN_100539c0(iVar1 + 0x45,param_3 + 1,bVar8);
  *(undefined1 *)(iVar1 + 0x44) = uVar7;
  bVar8 = 0x1f;
  if (*param_4 < 0x20) {
    bVar8 = *param_4;
  }
  uVar7 = FUN_100539c0(iVar1 + 0x85,param_4 + 1,bVar8);
  *(undefined1 *)(iVar1 + 0x84) = uVar7;
  if ((param_7 == (byte *)0x0) || (*param_7 == 0)) {
    uVar7 = FUN_10025890(iVar1 + 0xa5,0x3f);
    *(undefined1 *)(iVar1 + 0xa4) = uVar7;
  }
  else {
    if (*param_7 < 0x40) {
      bVar8 = *param_7;
    }
    else {
      bVar8 = 0x3f;
    }
    uVar7 = FUN_100539c0(iVar1 + 0xa5,param_7 + 1,bVar8);
    *(undefined1 *)(iVar1 + 0xa4) = uVar7;
  }
  iVar6 = local_20c;
  if (iVar3 == 0) {
    *(int *)(iVar1 + 0x28) = local_20c;
    local_20c = local_268;
  }
  else {
    *(int *)(iVar1 + 0x30) = iVar3;
    iVar6 = FUN_1002c3b0(param_1,(iVar3 + -1) * local_220 + 0x234,local_260,4,0);
    if (iVar6 != 4) {
      FUN_10027c30(1,9);
    }
    iVar6 = FUN_100247f0(param_1,local_220,local_260[0],0x2c);
    *(int *)(iVar1 + 0x28) = iVar6;
  }
  if (iVar6 == 0) {
    if (iVar3 == 0) {
      local_210 = local_268;
    }
    else {
      FUN_1002c440(param_1,(iVar3 + -1) * local_220 + 0x234,&local_268,4,0);
    }
  }
  else {
    FUN_1002c440(param_1,(iVar6 + -1) * local_220 + 0x22c,&local_268,4,0);
  }
  FUN_10024400(param_1,local_220,iVar4 + (uVar2 & local_1f4) * 8,iVar9 + (uVar2 & local_1f4) * 8,
               uVar2,iVar5,auStack_204);
  FUN_1002c440(param_1,(iVar5 + -1) * local_220 + 0x200,local_264,local_220,0);
  local_228 = local_228 + 1;
  local_208 = uVar2 + 1;
  local_214 = local_214 + 1;
  if (local_21c != 0) {
    FUN_10024150(param_1,local_220,auStack_204,local_21c,local_218 / local_220 + 1);
    local_21c = 0;
    local_218 = 0;
  }
  FUN_1002c440(param_1,0,&local_240,0x200,0);
  FUN_10052c10(local_264);
  FUN_10052c10(iVar4);
  FUN_1002c2c0(param_1);
  return uVar2;
}

