
int FUN_100262e0(int *param_1,int *param_2,short *param_3,short *param_4,undefined1 *param_5)

{
  int iVar1;
  byte local_110 [256];
  
  if (*param_1 == 0) {
    if (param_1[1] == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = FUN_100273a0(param_1[1],param_2,param_3,param_4);
    }
  }
  else if (*(char *)(param_1 + 1) == '\0') {
    *param_5 = 0;
    FUN_1002bce0(*param_1,local_110,0);
    if (*param_3 < (short)(local_110[0] + 3)) {
      *param_3 = -1;
    }
    else {
      *param_3 = *param_3 - (local_110[0] + 3);
      iVar1 = *param_2 - (local_110[0] + 1);
      *param_2 = iVar1;
      FUN_1007c240(iVar1,local_110);
      iVar1 = *param_2;
      *param_2 = iVar1 + -2;
      *(undefined2 *)(iVar1 + -2) = 0;
      *param_4 = *param_4 + 1;
    }
    *(undefined1 *)(param_1 + 1) = 1;
    iVar1 = *param_1;
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}

