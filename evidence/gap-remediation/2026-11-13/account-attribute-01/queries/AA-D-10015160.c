
void FUN_10015160(undefined4 param_1,int param_2,undefined4 param_3)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  char cVar8;
  byte *pbVar9;
  undefined1 auStack_510 [128];
  undefined4 local_44c;
  int local_448;
  uint local_444;
  undefined4 local_440;
  undefined4 local_43c;
  undefined4 local_438;
  undefined1 *local_41c;
  undefined1 *local_404;
  byte local_400;
  byte local_3ff [255];
  undefined1 auStack_300 [4];
  undefined1 auStack_2fc [524];
  undefined2 local_f0;
  undefined1 auStack_ee [170];
  short local_44;
  undefined1 local_42 [38];
  
  uVar2 = FUN_10056380(0,0);
  if (*(char *)(param_2 + 10) < '\0') {
    iVar3 = FUN_10007160(param_1);
    if (iVar3 == 0) {
      local_438 = FUN_10056380(0,0);
      FUN_10056ae0(local_438,100,0x100919f4);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,local_438);
      FUN_100563d0(local_438);
      FUN_100563d0(uVar2);
    }
    else {
      local_44c = 0;
      local_41c = auStack_510 + 0x80;
      while( true ) {
        cVar8 = FUN_1002ce00(iVar3,&local_44c,&local_400,&local_448,0,0,0,0);
        if (cVar8 == '\0') break;
        if ((local_448 == 0x666c6472) && ((local_444 & 1) == 0)) {
          local_404 = auStack_510 + 0x80;
          FUN_100073c0(param_1,&local_400,auStack_300);
          uVar4 = (uint)local_400;
          pbVar9 = local_3ff;
          while (bVar1 = uVar4 != 0, uVar4 = uVar4 - 1, bVar1) {
            *pbVar9 = ~*pbVar9;
            pbVar9 = pbVar9 + 1;
          }
          if (local_44 != 0) {
            local_44 = 1;
            local_42[0] = 0x78;
          }
          local_440 = FUN_10056380(0,0);
          FUN_100568b0(local_440,0x66,auStack_ee,local_f0);
          FUN_100568b0(local_440,0x69,local_3ff,local_400);
          FUN_100568b0(local_440,0x6a,local_42,local_44);
          FUN_100568b0(local_440,0x6e,auStack_2fc,8);
          iVar5 = FUN_10056d00(local_440);
          if (iVar5 == 0) {
            FUN_100563d0(local_440);
          }
          else {
            uVar6 = FUN_10052f80(iVar5);
            uVar7 = FUN_10053290(iVar5);
            FUN_100568b0(uVar2,0x65,uVar7,uVar6);
            FUN_10053310(iVar5);
            FUN_100563d0(local_440);
          }
        }
      }
      FUN_10052e90(iVar3);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
    }
  }
  else {
    local_43c = FUN_10056380(0,0);
    FUN_10056ae0(local_43c,100,0x100919c8);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_43c);
    FUN_100563d0(local_43c);
    FUN_100563d0(uVar2);
  }
  return;
}

