
int FUN_1007c2b0(byte *param_1,byte *param_2)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  
  bVar1 = *param_1;
  uVar4 = 0;
  while( true ) {
    if (bVar1 < uVar4) {
      return 0;
    }
    bVar2 = *param_2;
    bVar3 = *param_1;
    param_2 = param_2 + 1;
    param_1 = param_1 + 1;
    if ((uint)bVar3 - (uint)bVar2 != 0) break;
    uVar4 = uVar4 + 1;
  }
  return (uint)bVar3 - (uint)bVar2;
}

