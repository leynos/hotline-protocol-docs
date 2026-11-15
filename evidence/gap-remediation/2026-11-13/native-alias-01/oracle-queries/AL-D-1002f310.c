
undefined4
FUN_1002f310(undefined2 *param_1,char param_2,undefined1 *param_3,char *param_4,undefined4 param_5)

{
  undefined2 uVar1;
  bool bVar2;
  bool bVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  short sVar7;
  undefined4 uVar8;
  char local_90;
  char local_8f [9];
  undefined8 local_86;
  undefined8 local_7e;
  undefined8 local_76;
  undefined8 local_6e;
  undefined8 local_66;
  undefined8 local_5e;
  undefined8 local_56;
  undefined8 local_4e;
  
  if (((param_1 == (undefined2 *)0x0) || (param_3 == (undefined1 *)0x0)) || (param_4 == (char *)0x0)
     ) {
    uVar4 = 0xffffffce;
  }
  else {
    uVar1 = *param_1;
    uVar8 = *(undefined4 *)(param_1 + 1);
    local_86 = *(undefined8 *)(param_1 + 3);
    local_7e = *(undefined8 *)(param_1 + 7);
    local_76 = *(undefined8 *)(param_1 + 0xb);
    local_6e = *(undefined8 *)(param_1 + 0xf);
    local_66 = *(undefined8 *)(param_1 + 0x13);
    local_5e = *(undefined8 *)(param_1 + 0x17);
    local_56 = *(undefined8 *)(param_1 + 0x1b);
    local_4e = *(undefined8 *)(param_1 + 0x1f);
    sVar7 = 10;
    bVar2 = false;
    bVar3 = false;
    *param_3 = 0;
    while( true ) {
      uVar5 = 0xffffffff;
      sVar7 = sVar7 + -1;
      uVar4 = FUN_1002f210(param_1,param_4,param_3);
      if (((short)uVar4 != 0) || (*param_4 == '\0')) break;
      uVar5 = .glue::FSpOpenResFile(param_1,0);
      uVar4 = .glue::ResError();
      if ((short)uVar5 == -1) break;
      iVar6 = .glue::Get1IndResource(0x616c6973,1);
      uVar4 = .glue::ResError();
      if (iVar6 == 0) break;
      .glue::LoadResource(iVar6);
      uVar4 = .glue::ResError();
      if ((short)uVar4 != 0) break;
      uVar4 = .glue::FollowFinderAlias(param_1,iVar6,param_5,param_1,&local_90);
      if ((short)uVar4 == 0) {
        if (local_90 != '\0') {
          .glue::ChangedResource(iVar6);
          .glue::WriteResource(iVar6);
        }
        bVar2 = true;
        uVar4 = FUN_1002f210(param_1,local_8f,param_3);
        if (((short)uVar4 == 0) && ((bVar3 = false, local_8f[0] == '\0' || (param_2 == '\0')))) {
          bVar3 = true;
        }
      }
      .glue::CloseResFile(uVar5);
      uVar5 = 0xffffffff;
      if ((((short)uVar4 != 0) || (sVar7 < 1)) || (bVar3)) break;
    }
    if ((sVar7 == 0) && (!bVar3)) {
      uVar4 = 0xffffffd5;
    }
    if ((short)uVar5 != -1) {
      .glue::CloseResFile(uVar5);
    }
    if (((short)uVar4 != 0) && (bVar2)) {
      *param_1 = uVar1;
      *(undefined4 *)(param_1 + 1) = uVar8;
      *(undefined8 *)(param_1 + 3) = local_86;
      *(undefined8 *)(param_1 + 7) = local_7e;
      *(undefined8 *)(param_1 + 0xb) = local_76;
      *(undefined8 *)(param_1 + 0xf) = local_6e;
      *(undefined8 *)(param_1 + 0x13) = local_66;
      *(undefined8 *)(param_1 + 0x17) = local_5e;
      *(undefined8 *)(param_1 + 0x1b) = local_56;
      *(undefined8 *)(param_1 + 0x1f) = local_4e;
    }
  }
  return uVar4;
}

