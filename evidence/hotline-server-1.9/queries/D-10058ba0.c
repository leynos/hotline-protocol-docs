
undefined2 FUN_10058ba0(int param_1)

{
  undefined2 uVar1;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(int *)(param_1 + 0x10) == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined2 *)(*(int *)(param_1 + 0x10) + 0x18);
  }
  return uVar1;
}

