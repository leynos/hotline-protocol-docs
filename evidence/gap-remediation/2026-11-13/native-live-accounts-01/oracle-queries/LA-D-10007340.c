
void FUN_10007340(int param_1,char *param_2)

{
  undefined4 uVar1;
  
  if (((*(int *)(param_1 + 0xb0) != 0) && (param_2 != (char *)0x0)) && (*param_2 != '\0')) {
    uVar1 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),0,param_2,800,0);
    FUN_1002ba20();
    FUN_1002b2f0(uVar1);
  }
  return;
}

