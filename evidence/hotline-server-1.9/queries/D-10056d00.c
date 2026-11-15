
int FUN_10056d00(int *param_1)

{
  int iVar1;
  
  if (param_1 == (int *)0x0) {
    FUN_10027c30(1,2);
  }
  if (*param_1 == 0) {
    iVar1 = FUN_10052db0(param_1[1] + 2,0);
    *param_1 = iVar1;
  }
  return *param_1;
}

