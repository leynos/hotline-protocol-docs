
void FUN_10054210(byte *param_1,int param_2,undefined4 param_3,byte param_4,uint param_5)

{
  bool bVar1;
  
  if ((param_5 & 1) == 0) {
    while (bVar1 = param_2 != 0, param_2 = param_2 + -1, bVar1) {
      if (((&DAT_100945c8)[*param_1] & 0xde) == 0) {
        *param_1 = param_4;
      }
      param_1 = param_1 + 1;
    }
    return;
  }
  while (bVar1 = param_2 != 0, param_2 = param_2 + -1, bVar1) {
    if (((&DAT_100945c8)[*param_1] & 0xdc) == 0) {
      *param_1 = param_4;
    }
    param_1 = param_1 + 1;
  }
  return;
}

