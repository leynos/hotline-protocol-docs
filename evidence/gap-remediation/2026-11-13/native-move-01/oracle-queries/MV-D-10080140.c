
undefined4 FUN_10080140(short *param_1,short *param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  if (*param_1 == *param_2) {
    uVar1 = FUN_1007feb0((int)*param_1,*(undefined4 *)(param_1 + 1),param_1 + 3,
                         *(undefined4 *)(param_2 + 1),param_2 + 3,param_3);
  }
  else {
    uVar1 = 0xfffffae9;
  }
  return uVar1;
}

