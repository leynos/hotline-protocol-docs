
int FUN_10023180(undefined4 param_1,uint *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  uint local_25c;
  undefined4 local_258;
  int local_254;
  undefined1 auStack_250 [40];
  int local_228;
  int local_224;
  uint local_208;
  int local_204;
  uint local_200;
  undefined4 local_1fc;
  undefined4 local_1f8;
  undefined1 auStack_1ec [468];
  
  *param_2 = 0;
  FUN_1002c220(param_1,0x23);
  iVar1 = FUN_1002c3b0(param_1,0,&local_228,0x17c,0);
  if (iVar1 != 0x17c) {
    FUN_10027c30(1,9);
  }
  if (local_228 != 0x484c4e5a) {
    FUN_10027c30(1,8);
  }
  if (local_224 != 2) {
    FUN_10027c30(1,7);
  }
  if (((param_3 & 0xff) == 0) && (local_204 != 0)) {
    local_25c = local_200;
    iVar1 = FUN_10052a10();
    if (iVar1 == 0) {
      FUN_10027c30(3,0x65);
    }
    uVar2 = FUN_1002c3b0(param_1,local_208 * (local_204 + -1) + 0x200,iVar1,local_25c,0);
    if (local_25c != uVar2) {
      FUN_10027c30(1,9);
    }
    *param_2 = local_25c;
    FUN_1002c2c0(param_1);
  }
  else {
    local_258 = local_1fc;
    FUN_10025900(auStack_250);
    FUN_100248a0(auStack_250,param_1,local_208,local_1f8,&local_258,param_3);
    iVar1 = FUN_10025d80(auStack_250,&local_25c);
    *param_2 = local_25c;
    if ((param_3 & 0xff) == 0) {
      local_254 = FUN_10023de0(param_1,local_208,auStack_1ec,local_25c / local_208 + 1);
      FUN_1002c440(param_1,(local_254 + -1) * local_208 + 0x200,iVar1,local_25c,0);
      FUN_1002c440(param_1,0x24,&local_254,4,0);
      FUN_1002c440(param_1,0x28,&local_25c,4,0);
    }
    FUN_100259d0(auStack_250,0xffffffff);
    FUN_1002c2c0(param_1);
  }
  return iVar1;
}

