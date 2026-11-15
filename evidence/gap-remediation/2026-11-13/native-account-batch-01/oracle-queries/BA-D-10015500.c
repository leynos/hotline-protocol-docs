
void FUN_10015500(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined1 *puVar1;
  bool bVar2;
  bool bVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  short sVar9;
  char cVar10;
  byte *pbVar11;
  uint uVar12;
  undefined1 auStack_bd0 [128];
  uint local_b08;
  byte local_ae0;
  byte local_adf [51];
  undefined1 *local_aac;
  undefined1 *local_a94;
  undefined1 *local_a7c;
  undefined1 *local_a64;
  undefined1 *local_a4c;
  undefined1 *local_a34;
  undefined1 local_a30;
  undefined1 auStack_a2f [63];
  undefined1 local_9f0;
  undefined1 auStack_9ef [255];
  undefined1 local_8f0;
  undefined1 auStack_8ef [255];
  undefined1 auStack_7f0 [512];
  undefined2 local_5f0 [2];
  uint local_5ec;
  uint local_5e8;
  short local_3e0;
  undefined1 auStack_3de [66];
  undefined2 local_39c;
  undefined1 auStack_39a [66];
  ushort local_358;
  byte local_356 [34];
  ushort local_334;
  char local_332 [34];
  undefined1 auStack_310 [700];
  ushort local_54;
  undefined1 auStack_52 [42];
  
  puVar1 = auStack_bd0 + 0x80;
  if ((((*(byte *)(param_2 + 9) >> 1 & 1) == 0) && ((*(byte *)(param_2 + 10) >> 6 & 1) == 0)) &&
     ((*(byte *)(param_2 + 9) & 1) == 0)) {
    uVar4 = FUN_10056380(0,0);
    FUN_10056ae0(uVar4,100,0x1009195c);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar4);
    FUN_100563d0(uVar4);
    return;
  }
  uVar5 = FUN_10056550(param_4);
  if ((uVar5 & 0xffff) == 0) {
    uVar4 = FUN_10056380(0,0);
    FUN_10056ae0(uVar4,100,0x10091a0e);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar4);
    FUN_100563d0(uVar4);
  }
  else {
    uVar12 = 0;
    bVar3 = false;
    while ((uVar12 & 0xffff) < (uVar5 & 0xffff)) {
      uVar12 = uVar12 + 1;
      iVar6 = FUN_100566b0(param_4,uVar12,auStack_7f0,0x200);
      if (iVar6 == 0) {
        bVar3 = true;
      }
      else {
        local_aac = puVar1;
        uVar4 = FUN_10052cf0(auStack_7f0,iVar6,0);
        uVar7 = FUN_10056380(0,0);
        FUN_10056d70(uVar7,uVar4,0);
        local_ae0 = FUN_10056b60(uVar7,0x65,local_adf,0x1f);
        if (local_ae0 != 0) {
          uVar8 = (uint)local_ae0;
          pbVar11 = local_adf;
          while (bVar2 = uVar8 != 0, uVar8 = uVar8 - 1, bVar2) {
            *pbVar11 = ~*pbVar11;
            pbVar11 = pbVar11 + 1;
          }
        }
        FUN_1006cd50(local_5f0,0x2de);
        local_5f0[0] = 1;
        local_3e0 = FUN_10056b60(uVar7,0x66,auStack_3de,0x40);
        local_39c = FUN_10056b60(uVar7,0x6f,auStack_39a,0x40);
        local_358 = FUN_10056b60(uVar7,0x69,local_356,0x20);
        local_334 = FUN_10056b60(uVar7,0x6a,local_332,0x20);
        FUN_10056b60(uVar7,0x6e,&local_5ec,8);
        if ((local_3e0 == 0) && (local_358 == 0)) {
          if (local_ae0 == 0) {
            bVar3 = true;
          }
          else {
            if ((*(byte *)(param_2 + 9) & 1) == 0) {
              uVar4 = FUN_10056380(0,0);
              FUN_10056ae0(uVar4,100,0x10091893);
              FUN_10058a10(param_3,1);
              FUN_10058a70(param_3,uVar4);
              FUN_100563d0(uVar4);
              FUN_100563d0(uVar7);
              return;
            }
            local_a94 = puVar1;
            FUN_10007340(param_1,&local_ae0);
            FUN_10005f90(param_1,&local_ae0,param_2);
            FUN_10006fe0(param_1,param_2,0x100918f5,&local_ae0);
            FUN_100068e0(param_1,param_2,0x100918fc,&local_ae0);
          }
        }
        else {
          uVar8 = (uint)local_358;
          pbVar11 = local_356;
          while (bVar2 = uVar8 != 0, uVar8 = uVar8 - 1, bVar2) {
            *pbVar11 = ~*pbVar11;
            pbVar11 = pbVar11 + 1;
          }
          local_a30 = (undefined1)local_358;
          FUN_100539c0(auStack_a2f,local_356,local_358 & 0xff);
          FUN_100541e0(auStack_a2f,local_a30,0);
          if (((local_ae0 != 0) && (local_334 == 1)) && (local_332[0] == '\0')) {
            local_a7c = puVar1;
            FUN_100073c0(param_1,&local_ae0,auStack_310);
            if (local_54 < 0x20) {
              local_334 = local_54;
            }
            else {
              local_334 = 0x1f;
            }
            FUN_100539c0(local_332,auStack_52,local_334);
          }
          if ((local_ae0 != 0) &&
             (sVar9 = FUN_10053a60(local_adf,local_ae0,local_356,local_358,0), sVar9 != 0)) {
            if ((*(byte *)(param_2 + 10) >> 6 & 1) == 0) {
              uVar4 = FUN_10056380(0,0);
              FUN_10056ae0(uVar4,100,0x1009195c);
              FUN_10058a10(param_3,1);
              FUN_10058a70(param_3,uVar4);
              FUN_100563d0(uVar4);
              FUN_100563d0(uVar7);
              return;
            }
            local_a64 = puVar1;
            FUN_10007510(param_1,&local_ae0,local_5f0);
            local_9f0 = FUN_10054180(auStack_9ef,0xff,0x10091a2d,&local_ae0,&local_a30);
            FUN_10006fe0(param_1,param_2,0x10091a39,&local_9f0);
            FUN_100068e0(param_1,param_2,s_RenameRename_account___s_10091a3a + 6,&local_9f0);
          }
          cVar10 = FUN_100076b0(param_1,local_5f0);
          if (cVar10 == '\0') {
            if ((*(byte *)(param_2 + 9) >> 1 & 1) == 0) {
              uVar4 = FUN_10056380(0,0);
              FUN_10056ae0(uVar4,100,0x100917a7);
              FUN_10058a10(param_3,1);
              FUN_10058a70(param_3,uVar4);
              FUN_100563d0(uVar4);
              FUN_100563d0(uVar7);
              return;
            }
            local_b08 = local_5ec & 0xffffffef;
            if (((local_b08 & ~*(uint *)(param_2 + 8)) != 0) ||
               ((local_5e8 & ~*(uint *)(param_2 + 0xc)) != 0)) {
              uVar4 = FUN_10056380(0,0);
              FUN_10056ae0(uVar4,100,0x100917d3);
              FUN_10058a10(param_3,1);
              FUN_10058a70(param_3,uVar4);
              FUN_100563d0(uVar4);
              FUN_100563d0(uVar7);
              return;
            }
            local_a34 = puVar1;
            FUN_100071a0(param_1,local_5f0);
            FUN_10006fe0(param_1,param_2,0x10091877,&local_a30);
            FUN_100068e0(param_1,param_2,0x1009187e,&local_a30);
          }
          else if (local_ae0 == 0) {
            local_8f0 = FUN_10054180(auStack_8ef,0xff,0x10091809,&local_a30);
            uVar4 = FUN_10056380(0,0);
            FUN_10056ae0(uVar4,0x65,&local_8f0);
            FUN_10056a90(uVar4,0x6d,1);
            FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x68,uVar4);
            FUN_100563d0(uVar4);
          }
          else {
            if ((*(byte *)(param_2 + 10) >> 6 & 1) == 0) {
              uVar4 = FUN_10056380(0,0);
              FUN_10056ae0(uVar4,100,0x1009195c);
              FUN_10058a10(param_3,1);
              FUN_10058a70(param_3,uVar4);
              FUN_100563d0(uVar4);
              FUN_100563d0(uVar7);
              return;
            }
            local_a4c = puVar1;
            FUN_100075e0(param_1,local_5f0);
            FUN_10005d30(param_1,&local_ae0,local_5f0);
            FUN_10006fe0(param_1,param_2,0x100919ac,&local_a30);
            FUN_100068e0(param_1,param_2,0x100919b3,&local_a30);
          }
        }
        FUN_100563d0(uVar7);
      }
    }
    if (bVar3) {
      uVar4 = FUN_10056380(0,0);
      FUN_10056ae0(uVar4,100,0x10091a0e);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar4);
      FUN_100563d0(uVar4);
    }
    else {
      uVar4 = FUN_10056380(0,0);
      FUN_10058a70(param_3,uVar4);
      FUN_100563d0(uVar4);
    }
  }
  return;
}

