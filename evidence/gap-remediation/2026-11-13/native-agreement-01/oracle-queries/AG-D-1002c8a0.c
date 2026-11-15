
undefined4 FUN_1002c8a0(int param_1)

{
  undefined4 uVar1;
  undefined4 local_20 [7];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  uVar1 = .glue::FSpGetFInfo(param_1,local_20);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  return local_20[0];
}

