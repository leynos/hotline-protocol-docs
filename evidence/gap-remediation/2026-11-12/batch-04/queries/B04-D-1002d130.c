
int FUN_1002d130(undefined2 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  undefined4 uVar1;
  short sVar2;
  ushort *puVar3;
  undefined1 auStack_180 [18];
  byte *local_16e;
  undefined2 local_16a;
  undefined2 local_164;
  undefined4 local_160;
  undefined4 local_15c;
  ushort local_158;
  undefined4 local_150;
  undefined4 local_14a;
  undefined4 local_140;
  undefined4 local_138;
  undefined4 local_134;
  byte local_110;
  undefined1 auStack_10f [255];
  
  .glue::BlockMoveData(param_1 + 3,&local_110,*(byte *)(param_1 + 3) + 1);
  local_164 = 0;
  local_16e = &local_110;
  local_16a = *param_1;
  local_150 = *(undefined4 *)(param_1 + 1);
  uVar1 = .glue::PBGetCatInfoSync(auStack_180);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  FUN_1006cd50(param_2,0x48);
  *param_2 = 0x414d4143;
  param_2[1] = local_160;
  param_2[2] = local_15c;
  param_2[4] = (uint)local_158;
  FUN_10058070(local_138,param_2 + 0xd);
  FUN_10058070(local_134,param_2 + 0xf);
  *(ushort *)((int)param_2 + 0x46) = (ushort)local_110;
  .glue::BlockMoveData(auStack_10f,param_2 + 0x12,local_110);
  sVar2 = FUN_1007ee40(param_1,&local_110);
  if (sVar2 != 0) {
    local_110 = 0;
  }
  puVar3 = (ushort *)((int)param_2 + *(ushort *)((int)param_2 + 0x46) + 0x48);
  *puVar3 = (ushort)local_110;
  .glue::BlockMoveData(auStack_10f,puVar3 + 1,local_110);
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = local_14a;
  }
  if (param_4 != (undefined4 *)0x0) {
    *param_4 = local_140;
  }
  return (uint)*(ushort *)((int)param_2 + 0x46) + (uint)local_110 + 0x4a;
}

