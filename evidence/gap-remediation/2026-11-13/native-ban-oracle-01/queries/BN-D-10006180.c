
undefined4 FUN_10006180(int param_1,undefined4 param_2)

{
  char cVar1;
  uint uVar2;
  
  FUN_100064d0();
  uVar2 = 0;
  do {
    uVar2 = uVar2 + 1;
    if (*(uint *)(param_1 + 0x440) < uVar2) {
      return 0;
    }
    cVar1 = FUN_10009960(*(undefined4 *)(*(int *)(param_1 + 0x43c) + uVar2 * 4 + -4),param_2);
  } while (cVar1 == '\0');
  return 1;
}

