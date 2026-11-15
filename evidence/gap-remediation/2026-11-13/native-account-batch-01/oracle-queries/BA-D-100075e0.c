
void FUN_100075e0(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined1 local_118;
  undefined1 auStack_117 [271];
  
  if (*(int *)(param_1 + 0xb0) != 0) {
    local_118 = (undefined1)*(ushort *)(param_2 + 0x298);
    FUN_100539c0(auStack_117,param_2 + 0x29a,*(ushort *)(param_2 + 0x298) & 0xff);
    uVar1 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),&local_118,0x1008fed3,0x2a0,0);
    FUN_1002c220(uVar1,0x23);
    FUN_1002c5a0(uVar1,0x2de);
    FUN_1002c440(uVar1,0,param_2,0x2de,0);
    FUN_1002b2f0(uVar1);
  }
  return;
}

