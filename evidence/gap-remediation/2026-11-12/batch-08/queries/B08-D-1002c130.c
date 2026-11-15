
void FUN_1002c130(short *param_1,short *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char local_20 [20];
  
  if ((param_1 == (short *)0x0) || (param_2 == (short *)0x0)) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  if (*param_1 != *param_2) {
    FUN_10027c30(4,0x81);
  }
  uVar1 = FUN_1002e1b0((int)*param_2,*(undefined4 *)(param_2 + 1),param_2 + 3,local_20);
  if (local_20[0] == '\0') {
    FUN_10027c30(4,0x7d);
  }
  uVar2 = .glue::FSpCatMove(param_1,param_2);
  if ((short)uVar2 != 0) {
    FUN_10028190(uVar2,0,0);
  }
  if (*(char *)(param_1 + 3) != '\0') {
    *(undefined4 *)(param_1 + 1) = uVar1;
  }
  return;
}

