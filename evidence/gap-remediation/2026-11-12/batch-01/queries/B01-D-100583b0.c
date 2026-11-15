
void FUN_100583b0(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    FUN_1006daf0(*param_1);
    *(byte *)(param_1 + 0x13) = *(byte *)(param_1 + 0x13) & 0x7f;
  }
  return;
}

