
void FUN_10022830(undefined4 param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  int local_218;
  int local_214;
  undefined1 auStack_210 [16];
  undefined4 local_200;
  undefined4 local_1fc;
  undefined4 local_1ec;
  byte local_1bc;
  undefined1 auStack_1bb [31];
  undefined1 local_19c;
  undefined1 auStack_19b [399];
  
  FUN_1002c220(param_1,0x21);
  iVar1 = FUN_1002c3b0(param_1,0,&local_218,0x17c,0);
  if (iVar1 != 0x17c) {
    FUN_10027c30(1,9);
  }
  if (local_218 != 0x484c4e5a) {
    FUN_10027c30(1,8);
  }
  if (local_214 != 2) {
    FUN_10027c30(1,7);
  }
  FUN_1006f390(param_2,auStack_210);
  *(undefined4 *)(param_2 + 0x10) = local_1ec;
  *(undefined4 *)(param_2 + 0x14) = local_200;
  *(undefined4 *)(param_2 + 0x18) = local_1fc;
  bVar2 = 0x1f;
  if (local_1bc < 0x1f) {
    bVar2 = local_1bc;
  }
  bVar2 = FUN_100539c0(param_2 + 0x1d,auStack_1bb,bVar2);
  *(byte *)(param_2 + 0x1c) = bVar2;
  FUN_1006cd50(param_2 + bVar2 + 0x1d,0x1f - (uint)bVar2);
  bVar2 = FUN_100539c0(param_2 + 0x3d,auStack_19b,local_19c);
  *(byte *)(param_2 + 0x3c) = bVar2;
  FUN_1006cd50(param_2 + bVar2 + 0x3d,0xff - (uint)bVar2);
  FUN_1002c2c0(param_1);
  return;
}

