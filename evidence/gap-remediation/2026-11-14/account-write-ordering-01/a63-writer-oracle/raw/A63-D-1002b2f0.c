
void FUN_1002b2f0(int param_1)

{
  if (param_1 != 0) {
    if (*(short *)(param_1 + 0x50) != 0) {
      .glue::FSClose((int)*(short *)(param_1 + 0x50));
    }
    if (*(short *)(param_1 + 0x52) != 0) {
      .glue::FSClose((int)*(short *)(param_1 + 0x52));
    }
    FUN_10052c10(*(undefined4 *)(param_1 + 0x48));
    FUN_10052c10(*(undefined4 *)(param_1 + 0x4c));
    FUN_10052c10(param_1);
  }
  return;
}

