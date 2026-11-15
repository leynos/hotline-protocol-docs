
uint FUN_10008ab0(undefined4 param_1,int param_2,uint param_3)

{
  return (int)(uint)*(byte *)(param_2 + (param_3 >> 3) + 8) >> (7 - (param_3 & 7) & 0x3f) & 1;
}

