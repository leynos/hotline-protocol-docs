
undefined4 FUN_100572d0(int param_1,uint param_2,int *param_3)

{
  char cVar1;
  int local_20 [5];
  
  if ((param_1 != 0) && ((param_2 & 0xffff) != 0)) {
    if (*(int *)(param_1 + 0xc) == 0) {
      FUN_10056e20(param_1);
    }
    cVar1 = FUN_10057180(param_1,param_2,local_20);
    if (cVar1 != '\0') {
      *param_3 = *(int *)(param_1 + 4) +
                 *(int *)(*(int *)(param_1 + 8) +
                         (uint)*(ushort *)(*(int *)(param_1 + 0xc) + local_20[0] * 4 + 2) * 4);
      return 1;
    }
  }
  return 0;
}

