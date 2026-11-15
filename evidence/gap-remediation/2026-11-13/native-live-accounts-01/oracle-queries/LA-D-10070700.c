
void FUN_10070700(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  
  if (param_1 != 0) {
    uVar2 = *(undefined4 *)(param_1 + 4);
    cVar1 = .glue::OTEnterNotifier(uVar2);
    if (*(int *)(param_1 + 0x3c) == 0) {
      .glue::OTSndOrderlyDisconnect(uVar2);
    }
    else {
      .glue::OTAtomicSetBit(param_1 + 0x5e,1);
    }
    if (cVar1 != '\0') {
      .glue::OTLeaveNotifier(uVar2);
    }
  }
  return;
}

