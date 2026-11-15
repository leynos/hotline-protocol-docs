
int FUN_100233e0(undefined4 param_1,uint param_2,undefined4 param_3,int *param_4,undefined4 *param_5
                )

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char cVar9;
  int iVar7;
  undefined4 uVar8;
  undefined1 uVar10;
  byte bVar11;
  int iVar12;
  undefined1 auStack_410 [128];
  undefined1 auStack_348 [28];
  undefined1 *local_32c;
  int local_328 [9];
  undefined4 local_304;
  undefined4 local_300;
  undefined4 local_2fc;
  undefined4 local_2f8;
  undefined4 local_2f4;
  undefined1 auStack_2f0 [8];
  undefined4 local_2e8;
  byte local_2e4;
  undefined1 auStack_2e3 [63];
  byte local_2a4;
  undefined1 auStack_2a3 [31];
  byte local_284;
  undefined1 auStack_283 [67];
  int local_240;
  int local_23c;
  byte local_238;
  undefined1 auStack_237 [23];
  uint local_220;
  int local_1f8;
  uint local_1f4;
  
  FUN_1002c220(param_1,0x21);
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
  iVar3 = FUN_1002c3b0(param_1,local_220 * (local_1f8 + -1) + (param_2 & local_1f4) * 8 + 0x200,
                       auStack_348,8,0);
  if (iVar3 != 8) {
    FUN_10027c30(1,9);
  }
  iVar3 = FUN_10024280(param_1,local_220,param_2,auStack_348);
  if (iVar3 == 0) {
    FUN_10027c30(1,0xc);
  }
  iVar3 = FUN_1002c3b0(param_1,(iVar3 + -1) * local_220 + 0x200,local_328,0xe4,0);
  if (iVar3 != 0xe4) {
    FUN_10027c30(1,9);
  }
  iVar3 = 0x1e;
  uVar4 = FUN_1007c210(param_3);
  uVar5 = 0x200;
  if (local_220 < 0x201) {
    uVar5 = local_220;
  }
  if (uVar4 + 9 < uVar5) {
    uVar5 = uVar4 + 9;
  }
  local_240 = local_328[0];
  while ((bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1 && (local_240 != 0))) {
    iVar12 = local_220 * (local_240 + -1) + 0x200;
    uVar6 = FUN_1002c3b0(param_1,iVar12,&local_240,uVar5,0);
    if (uVar5 != uVar6) {
      FUN_10027c30(1,9);
    }
    if ((local_238 == uVar4) &&
       (cVar9 = FUN_1006cd80(auStack_237,param_3,uVar4), iVar2 = local_23c, cVar9 != '\0')) {
      local_32c = auStack_410 + 0x80;
      iVar7 = FUN_10052a10(local_23c);
      if (iVar7 != 0) {
        iVar3 = FUN_1002c3b0(param_1,iVar12 + (uVar4 + 4 & 0xfffffffc) + 8,iVar7,iVar2,0);
        if (iVar2 != iVar3) {
          FUN_10027c30(1,9);
        }
        if (param_5 != (undefined4 *)0x0) {
          *param_5 = local_304;
          uVar8 = FUN_100243a0(param_1,local_220,local_300);
          param_5[1] = uVar8;
          uVar8 = FUN_100243a0(param_1,local_220,local_2fc);
          param_5[2] = uVar8;
          uVar8 = FUN_100243a0(param_1,local_220,local_2f8);
          param_5[3] = uVar8;
          uVar8 = FUN_100243a0(param_1,local_220,local_2f4);
          param_5[4] = uVar8;
          param_5[5] = local_2e8;
          FUN_10057ce0(param_5 + 6,auStack_2f0);
          bVar11 = 0x3f;
          if (local_2e4 < 0x40) {
            bVar11 = local_2e4;
          }
          uVar10 = FUN_100539c0((int)param_5 + 0x21,auStack_2e3,bVar11);
          *(undefined1 *)(param_5 + 8) = uVar10;
          bVar11 = 0x1f;
          if (local_2a4 < 0x20) {
            bVar11 = local_2a4;
          }
          uVar10 = FUN_100539c0((int)param_5 + 0x61,auStack_2a3,bVar11);
          *(undefined1 *)(param_5 + 0x18) = uVar10;
          bVar11 = 0x3f;
          if (local_284 < 0x40) {
            bVar11 = local_284;
          }
          uVar10 = FUN_100539c0((int)param_5 + 0x81,auStack_283,bVar11);
          *(undefined1 *)(param_5 + 0x20) = uVar10;
        }
        *param_4 = iVar2;
        FUN_1002c2c0(param_1);
        return iVar7;
      }
      FUN_10027c30(3,0x65);
    }
  }
  FUN_10027c30(1,0xc);
  FUN_1002c2c0(param_1);
  return 0;
}

