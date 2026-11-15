
void FUN_1002c5a0(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(short *)(param_1 + 0x50) == 0) {
    FUN_10027c30(1,3);
  }
  uVar1 = .glue::SetEOF((int)*(short *)(param_1 + 0x50),param_2);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  return;
}

