
undefined4 FUN_100060d0(int param_1,undefined4 param_2)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    uVar2 = uVar2 + 1;
    if (*(uint *)(param_1 + 0x44c) < uVar2) {
      return 0;
    }
    cVar1 = FUN_10009960(*(undefined4 *)(*(int *)(param_1 + 0x448) + uVar2 * 4 + -4),param_2);
  } while (cVar1 == '\0');
  return 1;
}

