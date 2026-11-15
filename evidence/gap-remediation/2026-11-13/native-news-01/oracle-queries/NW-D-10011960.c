
void FUN_10011960(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined4 uVar2;
  char cVar8;
  undefined4 uVar3;
  short sVar7;
  byte *pbVar4;
  undefined1 uVar9;
  undefined4 uVar5;
  undefined4 uVar6;
  uint uVar10;
  byte bVar11;
  byte local_578 [36];
  byte local_554;
  undefined1 auStack_553 [35];
  char local_530 [552];
  undefined1 auStack_308 [7];
  byte local_301;
  ushort local_f8;
  undefined1 auStack_f6 [170];
  ushort local_4c;
  undefined1 auStack_4a [50];
  
  uVar2 = FUN_10056380(0,0);
  FUN_1006cd50(auStack_308,0x2de);
  cVar8 = FUN_100060d0(param_1,*(undefined4 *)(param_2 + 0x10));
  if (cVar8 == '\0') {
    cVar8 = FUN_10006180(param_1,*(undefined4 *)(param_2 + 0x10));
    if (cVar8 == '\0') {
      FUN_10056c70(param_4,0x69,local_578,0x21);
      FUN_10056c70(param_4,0x6a,&local_554,0x21);
      uVar3 = FUN_10056b90(param_4,0xa0);
      *(undefined4 *)(param_2 + 0x138) = uVar3;
      local_530[0] = '\0';
      FUN_10056c70(param_4,0x66,local_530,0x21);
      sVar7 = FUN_10056b90(param_4,0x68);
      if (local_578[0] == 0) {
        local_578[0] = 5;
        local_578[1] = 0x67;
        local_578[2] = 0x75;
        local_578[3] = 0x65;
        local_578[4] = 0x73;
        local_578[5] = 0x74;
      }
      else {
        uVar10 = (uint)local_578[0];
        pbVar4 = local_578;
        while( true ) {
          pbVar4 = pbVar4 + 1;
          bVar1 = uVar10 == 0;
          uVar10 = uVar10 - 1;
          if (bVar1) break;
          *pbVar4 = ~*pbVar4;
        }
        FUN_100541e0(local_578 + 1,local_578[0],0);
        uVar10 = (uint)local_578[0];
        pbVar4 = local_578;
        while( true ) {
          pbVar4 = pbVar4 + 1;
          bVar1 = uVar10 == 0;
          uVar10 = uVar10 - 1;
          if (bVar1) break;
          if (*pbVar4 == 0xd) {
            *pbVar4 = 0x2d;
          }
        }
      }
      FUN_100073c0(param_1,local_578,auStack_308);
      if ((local_554 == local_4c) &&
         (cVar8 = FUN_1006cd80(auStack_553,auStack_4a,local_4c), cVar8 != '\0')) {
        FUN_10056820(uVar2);
        FUN_10056a90(uVar2,0xa0,0xbe);
        FUN_10056a90(uVar2,0xa1,*(undefined4 *)(param_1 + 0x41c));
        FUN_10056ae0(uVar2,0xa2,param_1 + 0xcc);
        FUN_10058a70(param_3,uVar2);
        if (0x1f < local_f8) {
          local_f8 = 0x1f;
        }
        uVar9 = FUN_100539c0(param_2 + 0x59,auStack_f6,local_f8);
        *(undefined1 *)(param_2 + 0x58) = uVar9;
        bVar11 = local_578[0];
        if (0x1f < local_578[0]) {
          bVar11 = 0x1f;
        }
        uVar9 = FUN_100539c0(param_2 + 0x79,local_578 + 1,bVar11);
        *(undefined1 *)(param_2 + 0x78) = uVar9;
        if ((local_530[0] != '\0') && (sVar7 != 0)) {
          *(short *)(param_2 + 0x16) = sVar7;
          FUN_10004bf0(param_1,param_2,local_530,auStack_308);
          *(byte *)(param_2 + 0x14a) = *(byte *)(param_2 + 0x14a) & 0x7f | 0x80;
          FUN_100068e0(param_1,param_2,s_Login_successful_10090dcf);
          FUN_10056820(uVar2);
          FUN_100568b0(uVar2,0x6e,param_2 + 8,8);
          FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x162,uVar2);
        }
        FUN_10056820(uVar2);
        if ((local_301 >> 4 & 1) == 0) {
          if (*(int *)(param_1 + 8) != 0) {
            uVar3 = *(undefined4 *)(param_1 + 8);
            uVar5 = FUN_10053290();
            uVar6 = FUN_10052f80(*(undefined4 *)(param_1 + 8));
            FUN_100568b0(uVar2,0x65,uVar5,uVar6);
            FUN_10053310(uVar3);
          }
        }
        else {
          FUN_10056a90(uVar2,0x9a,1);
        }
        FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x6d,uVar2);
        if ((local_530[0] != '\0') && (sVar7 != 0)) {
          FUN_10006e80(param_1,param_2);
        }
        FUN_100563d0(uVar2);
        return;
      }
      uVar3 = 0x10090e36;
    }
    else {
      uVar3 = 0x10090e0b;
    }
  }
  else {
    uVar3 = 0x10090de0;
  }
  uVar5 = FUN_10056380(0,0);
  FUN_10056ae0(uVar5,100,uVar3);
  FUN_10058a10(param_3,1);
  FUN_10058a70(param_3,uVar5);
  FUN_100563d0(uVar5);
  uVar3 = FUN_10057d00();
  *(undefined4 *)(param_2 + 0x98) = uVar3;
  FUN_100068e0(param_1,param_2,s_Incorrect_login_Login_failed_10090e37 + 0x10);
  FUN_10057940(0,0x82,1);
  FUN_100563d0(uVar2);
  return;
}

