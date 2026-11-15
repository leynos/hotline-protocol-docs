
void FUN_1002c690(int param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  undefined1 local_110;
  undefined1 auStack_10f [259];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  if (0xff < param_3) {
    param_3 = 0xff;
  }
  local_110 = (undefined1)param_3;
  .glue::BlockMoveData(param_2,auStack_10f,param_3);
  uVar1 = FUN_1007ea90(param_1,&local_110);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  return;
}

