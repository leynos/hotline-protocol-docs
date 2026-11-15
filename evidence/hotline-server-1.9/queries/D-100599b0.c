
undefined4 FUN_100599b0(int param_1,uint param_2)

{
  undefined4 uVar1;
  
  if ((*(byte *)(param_1 + 0x2a) >> 1 & 1) == -(param_2 & 0xff) >> 0x1f) {
    uVar1 = 0;
  }
  else {
    *(byte *)(param_1 + 0x2a) = *(byte *)(param_1 + 0x2a) & 0xfd | 2;
    FUN_10082630(param_1,param_1 + 8);
    if (*(int *)(param_1 + 4) != 0) {
      FUN_10082630(*(undefined4 *)(param_1 + 4),param_1,param_2);
    }
    *(byte *)(param_1 + 0x2a) =
         (byte)((-(param_2 & 0xff) >> 0x1f) << 1) | *(byte *)(param_1 + 0x2a) & 0xfd;
    uVar1 = 1;
  }
  return uVar1;
}

