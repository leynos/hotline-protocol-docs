
bool FUN_1002e3d0(short *param_1,short *param_2,uint param_3,undefined4 param_4)

{
  byte bVar1;
  short sVar2;
  short sVar3;
  bool bVar4;
  byte *pbVar5;
  int local_20c;
  char local_1e0;
  undefined1 auStack_1df [3];
  undefined1 auStack_1dc [18];
  byte *local_1ca;
  short local_1c6;
  short local_1c0;
  byte local_1be;
  undefined4 local_1ac;
  undefined4 local_178;
  short local_170;
  undefined4 local_16e;
  byte local_16a [66];
  byte local_128 [276];
  
  .glue::BlockMoveData(param_1 + 3,local_128,*(byte *)(param_1 + 3) + 1);
  local_1c0 = -(ushort)(local_128[0] == 0);
  local_1ca = local_128;
  local_1c6 = *param_1;
  local_1ac = *(undefined4 *)(param_1 + 1);
  sVar2 = .glue::PBGetCatInfoSync(auStack_1dc);
  if ((sVar2 == 0) && ((local_1be & 0x10) != 0)) {
    if (param_3 < 6) {
      sVar2 = 0;
    }
    else {
      sVar2 = *param_2;
    }
    for (pbVar5 = (byte *)(param_2 + 1);
        (((bVar4 = sVar2 != 0, sVar2 = sVar2 + -1, bVar4 &&
          (pbVar5 = pbVar5 + 2, pbVar5 < (byte *)((int)param_2 + param_3))) &&
         (bVar1 = *pbVar5, bVar1 != 0)) && (pbVar5 + bVar1 + 1 <= (byte *)((int)param_2 + param_3)))
        ; pbVar5 = pbVar5 + bVar1 + 1) {
      .glue::BlockMoveData(pbVar5,local_128,*pbVar5 + 1);
      FUN_1002f080(local_128);
      local_1ca = local_128;
      local_1c0 = 0;
      if (local_128[0] == 0) {
        return false;
      }
      sVar3 = .glue::PBGetCatInfoSync(auStack_1dc);
      if (sVar3 != 0) {
        return false;
      }
      if ((local_1be & 0x10) == 0) {
        local_170 = local_1c6;
        local_16e = local_178;
        .glue::BlockMoveData(local_1ca,local_16a,*local_1ca + 1);
        sVar3 = FUN_1002f5a0(&local_170,&local_1e0,auStack_1df);
        if ((sVar3 != 0) || (local_1e0 == '\0')) {
          return false;
        }
        local_1ca = local_16a;
        local_1c6 = local_170;
        local_1ac = local_16e;
        local_1c0 = -(ushort)(local_16a[0] == 0);
        sVar3 = .glue::PBGetCatInfoSync(auStack_1dc);
        if ((sVar3 != 0) || ((local_1be & 0x10) == 0)) {
          return false;
        }
      }
    }
    sVar2 = .glue::FSMakeFSSpec((int)local_1c6,local_1ac,local_20c + 0x3535,param_4);
    bVar4 = sVar2 == 0;
  }
  else {
    bVar4 = false;
  }
  return bVar4;
}

