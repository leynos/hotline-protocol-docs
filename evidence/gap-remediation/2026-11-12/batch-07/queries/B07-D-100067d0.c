
uint FUN_100067d0(int param_1)

{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  uVar2 = FUN_1006e310(0x80000000,0x7fffffff);
  bVar1 = *(char *)(param_1 + 0x424) + 1;
  *(byte *)(param_1 + 0x424) = bVar1;
  uVar2 = uVar2 & 0xffffff00 | (uint)bVar1;
  do {
    if (uVar2 == 0) {
      uVar2 = 1;
    }
    puVar3 = *(undefined4 **)(param_1 + 0x420);
    while( true ) {
      if (puVar3 == (undefined4 *)0x0) {
        return uVar2;
      }
      if (puVar3[4] == uVar2) break;
      puVar3 = (undefined4 *)*puVar3;
    }
    uVar2 = uVar2 + 1;
  } while( true );
}

