
void FUN_1002bc30(int param_1,byte *param_2)

{
  undefined4 uVar1;
  
  if (((param_1 == 0) || (param_2 == (byte *)0x0)) || (*param_2 == 0)) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  uVar1 = .glue::FSpRename(param_1,param_2);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  if (*(char *)(param_1 + 6) != '\0') {
    .glue::BlockMoveData(param_2,param_1 + 6,*param_2 + 1);
  }
  return;
}

