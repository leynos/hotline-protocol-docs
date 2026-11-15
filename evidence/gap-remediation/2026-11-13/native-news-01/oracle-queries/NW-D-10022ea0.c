
undefined4 FUN_10022ea0(int param_1,uint param_2,undefined4 param_3,undefined4 param_4,int param_5)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int local_338 [2];
  undefined4 local_330;
  int local_32c;
  undefined1 local_328;
  undefined1 auStack_327 [247];
  int local_230;
  int local_22c;
  uint local_210;
  undefined1 auStack_1f4 [12];
  int local_1e8;
  uint local_1e4;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002c220(param_1,0x23);
  iVar1 = FUN_1002c3b0(param_1,0,&local_230,0x17c,0);
  if (iVar1 != 0x17c) {
    FUN_10027c30(1,9);
  }
  if (local_230 != 0x484c4e5a) {
    FUN_10027c30(1,8);
  }
  if (local_22c != 2) {
    FUN_10027c30(1,7);
  }
  iVar1 = (local_1e4 + 1) * 8;
  iVar2 = FUN_10052a10(iVar1);
  FUN_1002c3b0(param_1,local_210 * (local_1e8 + -1) + 0x200,iVar2,iVar1,0);
  iVar1 = FUN_10024280(param_1,local_210,param_2,iVar2 + (param_2 & local_1e4) * 8);
  if (iVar1 == 0) {
    FUN_10027c30(1,0xc);
  }
  uVar3 = FUN_1007c210(param_3);
  uVar6 = 0x1f;
  if (uVar3 < 0x20) {
    uVar6 = uVar3;
  }
  uVar3 = uVar6 + 4 & 0xfffffffc;
  iVar7 = uVar3 + 8;
  iVar1 = FUN_100247f0(param_1,local_210,iVar1,0);
  if (iVar1 == 0) {
    FUN_10027c30(1,9);
  }
  iVar4 = FUN_10023de0(param_1,local_210,auStack_1f4,(local_210 + iVar7 + param_5 + -1) / local_210)
  ;
  *(undefined4 *)((int)local_338 + uVar3 + 0xc) = 0;
  local_330 = 0;
  local_32c = param_5;
  local_328 = FUN_100539c0(auStack_327,param_3,uVar6);
  iVar5 = (iVar4 + -1) * local_210 + 0x200;
  iVar7 = FUN_1002c440(param_1,iVar5,&local_330,iVar7,0);
  iVar5 = iVar5 + iVar7;
  iVar7 = FUN_1002c440(param_1,iVar5,param_4,param_5,0);
  uVar6 = iVar5 + iVar7;
  iVar7 = local_210 - (uVar6 - (uVar6 / local_210) * local_210);
  if (iVar7 != 0) {
    FUN_1002c440(param_1,uVar6,&DAT_10096078,iVar7,0);
  }
  local_338[0] = iVar4;
  FUN_1002c440(param_1,(iVar1 + -1) * local_210 + 0x200,local_338,4,0);
  FUN_10052c10(iVar2);
  FUN_1002c2c0(param_1);
  return 1;
}

