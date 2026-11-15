
void FUN_10070610(int param_1)

{
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  if (param_1 != 0) {
    if (*(int *)(param_1 + 8) != 0) {
      .glue::OTDestroyTimerTask(*(undefined4 *)(param_1 + 8));
      *(undefined4 *)(param_1 + 8) = 0;
    }
    if ((*(int *)(param_1 + 0x2c) == 0x7fffffff) && (*(int *)(param_1 + 0x38) != 0)) {
      local_40 = 0;
      local_3c = 0;
      local_38 = 0;
      local_34 = 0;
      local_30 = 0;
      local_2c = 0;
      local_28 = 0;
      local_24 = 0;
      local_20 = 0;
      local_1c = *(undefined4 *)(param_1 + 0x38);
      .glue::OTSndDisconnect(*(undefined4 *)(param_1 + 4),&local_40);
      *(undefined4 *)(param_1 + 0x2c) = 0;
    }
    FUN_10073520(param_1);
    .glue::OTIoctl(*(undefined4 *)(param_1 + 4),0x4105,3);
    .glue::OTSndDisconnect(*(undefined4 *)(param_1 + 4),0);
    .glue::OTAtomicClearBit(param_1 + 0x5e,4);
  }
  return;
}

