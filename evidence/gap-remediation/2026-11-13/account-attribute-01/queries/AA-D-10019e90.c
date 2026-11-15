
void FUN_10019e90(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    uVar1 = uVar1 + 1;
    if (*(uint *)(param_1 + 0x74) < uVar1) {
      return;
    }
  } while (**(char **)(*(int *)(param_1 + 0x70) + uVar1 * 4 + -4) != '\x01');
  FUN_10082630(param_1,uVar1,1);
  FUN_10069fd0(param_1,uVar1,0x180);
  return;
}

