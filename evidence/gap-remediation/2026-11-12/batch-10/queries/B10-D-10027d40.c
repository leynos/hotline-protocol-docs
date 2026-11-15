
uint FUN_10027d40(short *param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  char cVar4;
  byte *pbVar3;
  uint uVar5;
  
  uVar5 = 0;
  uVar1 = .glue::LMGetResLoad();
  .glue::SetResLoad(1);
  puVar2 = (undefined4 *).glue::GetResource(0x454d5347,(int)*param_1);
  .glue::LMSetResLoad(uVar1);
  if (puVar2 != (undefined4 *)0x0) {
    cVar4 = .glue::HGetState(puVar2);
    .glue::HLock(puVar2);
    uVar1 = .glue::GetHandleSize(puVar2);
    uVar5 = FUN_10079b20(*puVar2,uVar1,(int)param_1[1],param_2,param_3);
    .glue::HSetState(puVar2,(int)cVar4);
  }
  if (uVar5 == 0) {
    if ((*param_1 == 3) && (param_1[1] == 0x65)) {
      pbVar3 = (byte *)(s_An_unknown_error_has_occured__No_1009397b + 0x1d);
    }
    else {
      pbVar3 = (byte *)0x1009397a;
    }
    uVar5 = (uint)*pbVar3;
    if (param_3 < *pbVar3) {
      uVar5 = param_3;
    }
    .glue::BlockMoveData(pbVar3 + 1,param_2,uVar5);
  }
  return uVar5;
}

