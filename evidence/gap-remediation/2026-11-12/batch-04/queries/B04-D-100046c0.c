
undefined4 FUN_100046c0(int param_1)

{
  short sVar1;
  undefined2 uVar2;
  undefined4 local_10;
  
  sVar1 = *(short *)(param_1 + 0xc4);
  *(short *)(param_1 + 0xc4) = sVar1 + 1;
  if (sVar1 == -1) {
    sVar1 = *(short *)(param_1 + 0xc4) + 1;
    *(short *)(param_1 + 0xc4) = sVar1;
  }
  else {
    sVar1 = *(short *)(param_1 + 0xc4);
  }
  uVar2 = FUN_1006e310(0x80000000,0x7fffffff);
  local_10 = CONCAT22(sVar1,uVar2);
  return local_10;
}

