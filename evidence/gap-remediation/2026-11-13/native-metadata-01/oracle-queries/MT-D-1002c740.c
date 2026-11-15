
byte FUN_1002c740(int param_1,undefined4 param_2,uint param_3,undefined4 *param_4)

{
  short sVar1;
  byte local_110;
  undefined1 auStack_10f [255];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  if (param_4 != (undefined4 *)0x0) {
    *param_4 = 0;
  }
  sVar1 = FUN_1007ee40(param_1,&local_110);
  if (sVar1 == 0) {
    if (param_3 < local_110) {
      local_110 = (byte)param_3;
    }
    .glue::BlockMoveData(auStack_10f,param_2,local_110);
  }
  else {
    local_110 = 0;
  }
  return local_110;
}

