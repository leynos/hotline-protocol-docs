
void FUN_100071a0(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined1 local_110;
  undefined1 auStack_10f [255];
  
  if (*(int *)(param_1 + 0xb0) != 0) {
    local_110 = (undefined1)*(ushort *)(param_2 + 0x298);
    FUN_100539c0(auStack_10f,param_2 + 0x29a,*(ushort *)(param_2 + 0x298) & 0xff);
    uVar1 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),0,&local_110,0x40,0);
    FUN_1002b670();
    uVar2 = FUN_1002af80(uVar1,0,0x1008fed3,0,0);
    FUN_1002b370(uVar2,0x48547564,0x48544c53);
    FUN_1002c220(uVar2,0x23);
    FUN_1002c5a0(uVar2,0x2de);
    FUN_1002c440(uVar2,0,param_2,0x2de,0);
    FUN_1002b2f0(uVar2);
    FUN_1002b2f0(uVar1);
  }
  return;
}

