
undefined4 FUN_1000ecc0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  char cVar2;
  undefined4 uVar3;
  int local_11c;
  int local_118 [2];
  undefined1 auStack_110 [264];
  
  iVar1 = FUN_1002b250(param_2);
  FUN_1002bce0(iVar1,auStack_110,0);
  cVar2 = FUN_1002b750(iVar1,0);
  if (cVar2 == '\0') {
    if (iVar1 != 0) {
      FUN_1002b2f0(iVar1);
    }
    uVar3 = 0;
  }
  else {
    FUN_1002c800(param_2,&local_11c,local_118);
    uVar3 = 0;
    if ((local_118[0] == 0x48544c43) && (local_11c == 0x48546674)) {
      uVar3 = 1;
    }
    if (iVar1 != 0) {
      FUN_1002b2f0(iVar1);
    }
  }
  return uVar3;
}

