
void FUN_10022670(int param_1,undefined4 param_2,byte *param_3,undefined4 param_4)

{
  bool bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  undefined4 local_428;
  undefined4 local_424;
  undefined1 auStack_420 [16];
  undefined4 local_410;
  undefined4 local_40c;
  undefined4 local_408;
  undefined4 local_3f0;
  undefined4 local_3ec;
  undefined4 local_3e8;
  undefined4 local_3e4;
  undefined4 local_3e0;
  undefined4 local_3dc;
  undefined1 local_3cc;
  undefined1 auStack_3cb [31];
  undefined1 auStack_3ac [388];
  byte local_228 [532];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1006cd50(&local_428,0x400);
  local_428 = 0x484c4e5a;
  local_424 = 2;
  FUN_1006f2e0(auStack_420);
  local_410 = 1;
  local_40c = 1;
  local_408 = 0x100;
  local_3f0 = 1;
  local_3ec = 1;
  local_3e8 = 1;
  local_3e4 = 1;
  local_3e0 = 2;
  local_3dc = 0x1f;
  bVar2 = 0x1f;
  if (*param_3 < 0x20) {
    bVar2 = *param_3;
  }
  local_3cc = FUN_100539c0(auStack_3cb,param_3 + 1,bVar2);
  FUN_1007c240(auStack_3ac,param_4);
  local_228[0] = local_228[0] | 0x80;
  iVar3 = 1;
  uVar4 = 1;
  while (bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1) {
    local_228[uVar4 >> 3] = local_228[uVar4 >> 3] | (byte)(1 << (7 - (uVar4 & 7) & 0x3f));
    uVar4 = uVar4 + 1;
  }
  FUN_1002b370(param_1,0x484c4e5a,0x48544c53);
  FUN_1002c220(param_1,0x23);
  FUN_1002c440(param_1,0,&local_428,0x400,0);
  FUN_1002c2c0(param_1);
  return;
}

