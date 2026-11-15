
void FUN_1002fb00(undefined4 param_1,undefined2 *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int local_10c;
  int local_e0 [2];
  undefined4 local_d8;
  undefined4 local_d4;
  ushort local_d0;
  char local_c8 [64];
  undefined1 auStack_88 [18];
  char *local_76;
  undefined2 local_72;
  short local_6c;
  byte local_6a;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_58;
  
  local_e0[0] = 0;
  uVar2 = 0xffffffff;
  uVar3 = 0xffffffff;
  .glue::BlockMoveData(param_2 + 3,local_c8,*(byte *)(param_2 + 3) + 1);
  local_6c = -(ushort)(local_c8[0] == '\0');
  local_76 = local_c8;
  local_72 = *param_2;
  local_58 = *(undefined4 *)(param_2 + 1);
  uVar1 = .glue::PBGetCatInfoSync(auStack_88);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  if ((local_6a & 0x10) == 0) {
    local_d8 = local_68;
    local_d4 = local_64;
  }
  else {
    local_d8 = 0x66647270;
    local_d4 = 0x4d414353;
  }
  uVar1 = .glue::NewAlias(0,param_2,local_e0);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  .glue::FSpCreateResFile(param_1,local_d4,local_d8,0);
  uVar1 = .glue::ResError();
  if ((short)uVar1 == 0) {
    uVar3 = .glue::CurResFile();
    uVar2 = .glue::FSpOpenResFile(param_1,3);
    if ((short)uVar2 == -1) {
      uVar1 = .glue::ResError();
    }
    else {
      .glue::UseResFile(uVar2);
      .glue::AddResource(local_e0[0],0x616c6973,0,local_10c + 0x3535);
      uVar1 = .glue::ResError();
      if ((short)uVar1 == 0) {
        local_e0[0] = 0;
        .glue::CloseResFile(uVar2);
        .glue::UseResFile(uVar3);
        uVar1 = .glue::FSpGetFInfo(param_1,&local_d8);
        if ((short)uVar1 == 0) {
          local_d0 = local_d0 & 0xfeff | 0x8000;
          uVar1 = .glue::FSpSetFInfo(param_1,&local_d8);
          if ((short)uVar1 == 0) {
            return;
          }
        }
      }
    }
  }
  if (local_e0[0] != 0) {
    .glue::DisposeHandle(local_e0[0]);
  }
  if ((short)uVar2 != -1) {
    .glue::CloseResFile(uVar2);
    .glue::FSpDelete(param_1);
  }
  if ((short)uVar3 != -1) {
    .glue::UseResFile(uVar3);
  }
  FUN_10028190(uVar1,0,0);
  return;
}

