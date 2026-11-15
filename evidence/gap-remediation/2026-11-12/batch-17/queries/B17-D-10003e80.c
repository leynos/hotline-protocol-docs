
undefined4 FUN_10003e80(undefined4 param_1,char *param_2,int *param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*param_3 != 0) {
    FUN_10052e90(*param_3);
    *param_3 = 0;
  }
  if ((param_2 == (char *)0x0) || (*param_2 == '\0')) {
    uVar1 = 0;
  }
  else {
    iVar2 = FUN_10052c50(*param_2,0);
    *param_3 = iVar2;
    uVar1 = FUN_10053290();
    FUN_100539c0(uVar1,param_2 + 1,*param_2);
    FUN_10053310(iVar2);
    uVar1 = 1;
  }
  return uVar1;
}

