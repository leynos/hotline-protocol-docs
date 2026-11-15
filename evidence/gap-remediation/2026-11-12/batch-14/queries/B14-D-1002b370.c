
void FUN_1002b370(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(short *)(param_1 + 0x50) != 0) {
    FUN_10027c30(1,0x73);
  }
  uVar1 = .glue::FSpCreate(param_1,param_3,param_2,0);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  return;
}

