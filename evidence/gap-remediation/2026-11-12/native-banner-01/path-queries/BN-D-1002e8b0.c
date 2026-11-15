
undefined4
FUN_1002e8b0(short *param_1,byte *param_2,short *param_3,undefined4 param_4,byte *param_5,
            short *param_6)

{
  undefined4 uVar1;
  int iVar2;
  char cVar3;
  byte bVar4;
  undefined1 *puVar5;
  undefined1 uStack00000000;
  undefined1 auStack_400 [128];
  byte local_340;
  short local_33e;
  undefined4 local_33c [6];
  undefined1 *local_324;
  undefined1 local_320 [64];
  short local_2e0;
  undefined4 local_2de;
  undefined8 local_2da;
  undefined8 local_2d2;
  undefined8 local_2ca;
  undefined8 local_2c2;
  undefined8 local_2ba;
  undefined8 local_2b2;
  undefined8 local_2aa;
  undefined8 local_2a2;
  undefined1 auStack_298 [18];
  undefined8 *local_286;
  short local_282;
  undefined2 local_27c;
  byte local_27a;
  undefined4 local_268;
  undefined4 local_234;
  byte local_228;
  undefined1 auStack_227 [27];
  undefined1 auStack_20c [5];
  undefined1 auStack_207 [223];
  byte local_128 [268];
  
  if (param_5 == (byte *)0x0) {
    local_228 = 0;
  }
  else {
    .glue::BlockMoveData(param_5,&local_228,*param_5 + 1);
    FUN_1002f080(&local_228);
  }
  if ((param_2 == (byte *)0x0) || (*param_2 == 0)) {
    local_128[0] = 0;
  }
  else {
    .glue::BlockMoveData(param_2,local_128,*param_2 + 1);
    if (local_128[local_128[0]] == 0xd) {
      local_128[0] = local_128[0] - 1;
    }
  }
  if (param_1 == (short *)0xfffffffe) {
    if (((local_128[0] == 0) && (param_3 == (short *)0x0)) && (local_228 != 0)) {
      uVar1 = .glue::FSMakeFSSpec(0,0,&local_228,param_6);
      if ((short)uVar1 == 0) {
        return 1;
      }
      if ((short)uVar1 == -0x2b) {
        return 0;
      }
      FUN_10028190(uVar1,0,0);
    }
    uVar1 = .glue::FSMakeFSSpec(0,0,0,&local_2e0);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
  }
  else if (param_1 == (short *)0xffffffff) {
    uVar1 = .glue::FSMakeFSSpec(0xffffffff,0,0,&local_2e0);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
  }
  else if (param_1 == (short *)0xfffffffb) {
    uVar1 = .glue::FindFolder(0xffff8000,0x6465736b,1,&local_33e,local_33c);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
    uVar1 = .glue::FSMakeFSSpec((int)local_33e,local_33c[0],0,&local_2e0);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
  }
  else if (param_1 == (short *)0xfffffffd) {
    uVar1 = .glue::FindFolder(0xffff8000,0x74656d70,1,&local_33e,local_33c);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
    uVar1 = .glue::FSMakeFSSpec((int)local_33e,local_33c[0],0,&local_2e0);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
  }
  else if (param_1 == (short *)0xfffffffc) {
    uVar1 = .glue::FindFolder(0xffff8000,0x70726566,1,&local_33e,local_33c);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
    uVar1 = .glue::FSMakeFSSpec((int)local_33e,local_33c[0],0,&local_2e0);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
  }
  else {
    local_2e0 = *param_1;
    local_2de = *(undefined4 *)(param_1 + 1);
    local_2da = *(undefined8 *)(param_1 + 3);
    local_2d2 = *(undefined8 *)(param_1 + 7);
    local_2ca = *(undefined8 *)(param_1 + 0xb);
    local_2c2 = *(undefined8 *)(param_1 + 0xf);
    local_2ba = *(undefined8 *)(param_1 + 0x13);
    local_2b2 = *(undefined8 *)(param_1 + 0x17);
    local_2aa = *(undefined8 *)(param_1 + 0x1b);
    local_2a2 = *(undefined8 *)(param_1 + 0x1f);
  }
  if (local_128[0] == 0) {
    if ((param_3 != (short *)0x0) && (*param_3 != 0)) {
      if (local_228 == 0) {
        local_228 = FUN_1006e820(param_3,0xffff,auStack_227,0xff,0,0);
        FUN_1002f080(&local_228);
        if (*param_3 != 1) {
          *param_3 = *param_3 + -1;
          local_324 = auStack_400 + 0x80;
          cVar3 = FUN_1002e3d0(&local_2e0,param_3,param_4,&local_2e0);
          if (cVar3 == '\0') {
            FUN_10027c30(4,0x68);
          }
          *param_3 = *param_3 + 1;
        }
      }
      else {
        cVar3 = FUN_1002e3d0(&local_2e0,param_3,param_4,&local_2e0);
        if (cVar3 == '\0') {
          FUN_10027c30(4,0x68);
        }
      }
    }
  }
  else if (local_228 == 0) {
    iVar2 = FUN_1006cf00(0xd,local_128 + 1,local_128[0]);
    if (iVar2 == 0) {
      .glue::BlockMoveData(local_128,&local_228,local_128[0] + 1);
    }
    else {
      local_228 = (byte)(local_128 + ((uint)local_128[0] - (iVar2 + 1)) + 1);
      .glue::BlockMoveData
                (iVar2 + 1,auStack_227,
                 (uint)(local_128 + ((uint)local_128[0] - (iVar2 + 1)) + 1) & 0xff);
      local_128[0] = (local_128[0] - local_228) - 1;
      cVar3 = FUN_1002e620(&local_2e0,local_128,&local_2e0);
      if (cVar3 == '\0') {
        FUN_10027c30(4,0x68);
      }
    }
    FUN_1002f080(&local_228);
  }
  else {
    cVar3 = FUN_1002e620(&local_2e0,local_128,&local_2e0);
    if (cVar3 == '\0') {
      FUN_10027c30(4,0x68);
    }
  }
  if (local_228 == 0) {
    *param_6 = local_2e0;
    *(undefined4 *)(param_6 + 1) = local_2de;
    *(undefined8 *)(param_6 + 3) = local_2da;
    *(undefined8 *)(param_6 + 7) = local_2d2;
    *(undefined8 *)(param_6 + 0xb) = local_2ca;
    *(undefined8 *)(param_6 + 0xf) = local_2c2;
    *(undefined8 *)(param_6 + 0x13) = local_2ba;
    *(undefined8 *)(param_6 + 0x17) = local_2b2;
    *(undefined8 *)(param_6 + 0x1b) = local_2aa;
    *(undefined8 *)(param_6 + 0x1f) = local_2a2;
    uVar1 = 1;
  }
  else {
    if ((&uStack00000000 == (undefined1 *)0x2da) || (local_2da._0_1_ == '\0')) {
      local_320[0] = 0;
      local_286 = (undefined8 *)local_320;
      local_27c = 0xffff;
    }
    else {
      local_286 = &local_2da;
      local_27c = 0;
    }
    local_282 = local_2e0;
    local_268 = local_2de;
    uVar1 = .glue::PBGetCatInfoSync(auStack_298);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
    bVar4 = local_27a >> 4 & 1;
    if (&uStack00000000 != (undefined1 *)0x340) {
      local_340 = bVar4;
    }
    if (bVar4 == 0) {
      local_33c[0] = local_234;
    }
    else {
      local_33c[0] = local_268;
    }
    if (local_340 == 0) {
      FUN_10028190(0xffffff88,0,0);
    }
    uVar1 = .glue::FSMakeFSSpec((int)local_2e0,local_33c[0],&local_228,param_6);
    if ((short)uVar1 == 0) {
      uVar1 = 1;
    }
    else {
      if (0x20 < local_228) {
        uVar1 = FUN_1006d1f0(auStack_227,local_228,local_228);
        iVar2 = FUN_1006cf00(0x2e,auStack_227,local_228);
        if (iVar2 == 0) {
          FUN_10054180(auStack_20c,5,0x10093ca5,uVar1);
        }
        else {
          puVar5 = auStack_227 + ((uint)local_228 - iVar2);
          if ((undefined1 *)0x10 < puVar5) {
            puVar5 = (undefined1 *)0x10;
          }
          FUN_100539c0(auStack_207 + -(int)puVar5,iVar2,puVar5);
          FUN_10054180(auStack_20c + -(int)puVar5,5,0x10093ca5,uVar1);
        }
        local_228 = 0x20;
        uVar1 = .glue::FSMakeFSSpec((int)local_2e0,local_33c[0],&local_228,param_6);
        if ((short)uVar1 == 0) {
          return 1;
        }
      }
      if ((short)uVar1 == -0x2b) {
        uVar1 = 0;
      }
      else {
        FUN_10028190(uVar1,0,0);
        uVar1 = 0;
      }
    }
  }
  return uVar1;
}

