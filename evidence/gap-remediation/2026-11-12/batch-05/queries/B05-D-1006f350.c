
undefined4 FUN_1006f350(undefined4 *param_1,undefined4 *param_2)

{
  *param_2 = *param_1;
  *(undefined2 *)(param_2 + 1) = *(undefined2 *)(param_1 + 1);
  *(undefined2 *)((int)param_2 + 6) = *(undefined2 *)((int)param_1 + 6);
  *(undefined1 *)(param_2 + 2) = *(undefined1 *)(param_1 + 2);
  *(undefined1 *)((int)param_2 + 9) = *(undefined1 *)((int)param_1 + 9);
  *(undefined4 *)((int)param_2 + 10) = *(undefined4 *)((int)param_1 + 10);
  *(undefined2 *)((int)param_2 + 0xe) = *(undefined2 *)((int)param_1 + 0xe);
  return 0x10;
}

