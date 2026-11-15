
uint FUN_10019110(int param_1)

{
  uint uVar1;
  
  *(undefined4 *)(param_1 + 0x78) = 0;
  FUN_100691c0(*(undefined4 *)(param_1 + 0x70),0,0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x74),0,0);
  uVar1 = FUN_1001ac30(param_1);
  return (-uVar1 | uVar1) >> 0x1f;
}

