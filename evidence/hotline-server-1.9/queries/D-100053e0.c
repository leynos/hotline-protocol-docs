
uint FUN_100053e0(int param_1,uint param_2)

{
  return (int)(uint)*(byte *)(param_1 + (param_2 >> 3)) >> (7 - (param_2 & 7) & 0x3f) & 1;
}

