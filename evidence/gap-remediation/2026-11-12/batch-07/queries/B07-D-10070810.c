
void FUN_10070810(int param_1,short *param_2,uint param_3)

{
  undefined4 uVar1;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if ((param_3 < 0xc) || (*param_2 != 2)) {
    FUN_10027c30(8,0x65);
  }
  if (*(int *)(param_1 + 0xc) == 1) {
    .glue::OTSndDisconnect(*(undefined4 *)(param_1 + 4),0);
    .glue::OTUnbind(*(undefined4 *)(param_1 + 4));
    .glue::OTCloseProvider(*(undefined4 *)(param_1 + 4));
    uVar1 = FUN_10071d50(param_1,1);
    *(undefined4 *)(param_1 + 4) = uVar1;
  }
  FUN_10072050(param_1,param_2[1],0x10);
  return;
}

