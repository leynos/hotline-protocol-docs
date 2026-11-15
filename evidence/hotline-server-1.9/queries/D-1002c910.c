
void FUN_1002c910(undefined2 *param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  char local_c0 [64];
  undefined1 auStack_80 [18];
  char *local_6e;
  undefined2 local_6a;
  short local_64;
  undefined4 local_50;
  undefined4 local_38;
  undefined4 local_34;
  
  if (param_1 == (undefined2 *)0x0) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  .glue::BlockMoveData(param_1 + 3,local_c0,*(byte *)(param_1 + 3) + 1);
  local_64 = -(ushort)(local_c0[0] == '\0');
  local_6e = local_c0;
  local_6a = *param_1;
  local_50 = *(undefined4 *)(param_1 + 1);
  uVar1 = .glue::PBGetCatInfoSync(auStack_80);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  if (param_2 != 0) {
    FUN_10058070(local_34,param_2);
  }
  if (param_3 != 0) {
    FUN_10058070(local_38,param_3);
  }
  return;
}

