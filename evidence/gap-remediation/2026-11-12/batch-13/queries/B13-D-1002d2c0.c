
void FUN_1002d2c0(short *param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  ushort *puVar3;
  ushort uVar4;
  int local_180;
  undefined1 auStack_17c [18];
  undefined1 *local_16a;
  short local_166;
  undefined2 local_160;
  undefined4 local_15c;
  undefined4 local_158;
  ushort local_154;
  undefined4 local_14c;
  int local_130;
  undefined1 local_110;
  undefined1 auStack_10f [259];
  
  .glue::BlockMoveData(param_1 + 3,&local_110,*(byte *)(param_1 + 3) + 1);
  FUN_1006cd50(auStack_17c,0x6c);
  local_160 = 0;
  local_16a = &local_110;
  local_166 = *param_1;
  local_14c = *(undefined4 *)(param_1 + 1);
  uVar1 = .glue::PBGetCatInfoSync(auStack_17c);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  local_160 = 0;
  local_16a = &local_110;
  local_166 = *param_1;
  local_14c = *(undefined4 *)(param_1 + 1);
  local_15c = *(undefined4 *)(param_2 + 4);
  local_158 = *(undefined4 *)(param_2 + 8);
  local_154 = (ushort)*(undefined4 *)(param_2 + 0x10);
  .glue::GetDateTime(&local_180);
  if (local_180 == local_130) {
    local_180 = local_180 + 1;
  }
  local_154 = local_154 & 0x7eff;
  local_130 = local_180;
  uVar1 = .glue::PBSetCatInfoSync(auStack_17c);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  iVar2 = param_2 + (uint)*(ushort *)(param_2 + 0x46);
  puVar3 = (ushort *)(iVar2 + 0x48);
  if (puVar3 < (ushort *)(param_2 + param_3)) {
    uVar4 = *puVar3;
    if (uVar4 != 0) {
      if (0xff < uVar4) {
        uVar4 = 0xff;
      }
      local_110 = (undefined1)uVar4;
      .glue::BlockMoveData(iVar2 + 0x4a,auStack_10f);
      FUN_1007ea90(param_1,&local_110);
    }
  }
  .glue::FlushVol(0,(int)*param_1);
  return;
}

