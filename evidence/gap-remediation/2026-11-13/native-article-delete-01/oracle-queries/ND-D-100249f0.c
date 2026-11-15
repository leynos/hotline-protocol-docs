
void FUN_100249f0(undefined4 param_1,int param_2,undefined4 param_3,int param_4,uint param_5,
                 int param_6,int *param_7)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  uint local_680;
  undefined4 local_67c;
  undefined4 local_678;
  undefined1 auStack_674 [44];
  int local_648;
  int local_640;
  undefined1 auStack_590 [44];
  undefined4 local_564;
  undefined4 local_55c;
  undefined1 auStack_4ac [44];
  undefined4 local_480;
  undefined4 local_478;
  undefined1 auStack_3c8 [44];
  undefined4 local_39c;
  undefined4 local_394;
  undefined1 auStack_2e4 [44];
  undefined4 local_2b8;
  undefined4 local_2b0;
  undefined1 auStack_200 [44];
  undefined4 local_1d4;
  undefined4 local_1cc;
  undefined1 auStack_11c [44];
  undefined4 local_f0;
  undefined4 local_e8;
  
  if (param_6 != 0) {
    iVar1 = FUN_1002c3b0(param_1,(param_6 + -1) * param_2 + 0x200,auStack_674,0xe4,0);
    if (iVar1 != 0xe4) {
      FUN_10027c30(1,9);
    }
    if (local_640 != 0) {
      iVar1 = FUN_1002c3b0(param_1,(local_640 + -1) * param_2 + 0x200,auStack_590,0xe4,0);
      if (iVar1 != 0xe4) {
        FUN_10027c30(1,9);
      }
      iVar1 = FUN_100014b0(local_55c);
      if (iVar1 != 0) {
        iVar2 = FUN_100013a0(param_1,(iVar1 + -1) * param_2 + 0x200,auStack_3c8,0xe4,0);
        if (iVar2 != 0xe4) {
          FUN_10027c30(1,9);
        }
        uVar3 = FUN_100014b0(local_394);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        uVar3 = FUN_100014b0(local_39c);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        FUN_10025060(param_1,param_2,param_3,iVar1);
        uVar4 = FUN_100243a0(param_1,param_2,iVar1);
        FUN_10024620(param_1,param_2,param_4 + (uVar4 & param_5) * 8,uVar4,param_3);
        *param_7 = *param_7 + -1;
      }
      iVar1 = FUN_100014b0(local_564);
      if (iVar1 != 0) {
        iVar2 = FUN_100013a0(param_1,(iVar1 + -1) * param_2 + 0x200,auStack_2e4,0xe4,0);
        if (iVar2 != 0xe4) {
          FUN_10027c30(1,9);
        }
        uVar3 = FUN_100014b0(local_2b0);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        uVar3 = FUN_100014b0(local_2b8);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        FUN_10025060(param_1,param_2,param_3,iVar1);
        uVar4 = FUN_100243a0(param_1,param_2,iVar1);
        FUN_10024620(param_1,param_2,param_4 + (uVar4 & param_5) * 8,uVar4,param_3);
        *param_7 = *param_7 + -1;
      }
      FUN_10025060(param_1,param_2,param_3,local_640);
      if (local_640 == 0) {
        uVar4 = 0;
      }
      else {
        iVar1 = FUN_100013a0(param_1,(local_640 + -1) * param_2 + 0x224,&local_67c,4,0);
        if (iVar1 == 4) {
          uVar4 = FUN_100014b0(local_67c);
        }
        else {
          uVar4 = 0;
        }
      }
      FUN_10024620(param_1,param_2,param_4 + (uVar4 & param_5) * 8,uVar4,param_3);
      *param_7 = *param_7 + -1;
    }
    if (local_648 != 0) {
      iVar1 = FUN_1002c3b0(param_1,(local_648 + -1) * param_2 + 0x200,auStack_4ac,0xe4,0);
      if (iVar1 != 0xe4) {
        FUN_10027c30(1,9);
      }
      iVar1 = FUN_100014b0(local_478);
      if (iVar1 != 0) {
        iVar2 = FUN_100013a0(param_1,(iVar1 + -1) * param_2 + 0x200,auStack_200,0xe4,0);
        if (iVar2 != 0xe4) {
          FUN_10027c30(1,9);
        }
        uVar3 = FUN_100014b0(local_1cc);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        uVar3 = FUN_100014b0(local_1d4);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        FUN_10025060(param_1,param_2,param_3,iVar1);
        uVar4 = FUN_100243a0(param_1,param_2,iVar1);
        FUN_10024620(param_1,param_2,param_4 + (uVar4 & param_5) * 8,uVar4,param_3);
        *param_7 = *param_7 + -1;
      }
      iVar1 = FUN_100014b0(local_480);
      if (iVar1 != 0) {
        iVar2 = FUN_100013a0(param_1,(iVar1 + -1) * param_2 + 0x200,auStack_11c,0xe4,0);
        if (iVar2 != 0xe4) {
          FUN_10027c30(1,9);
        }
        uVar3 = FUN_100014b0(local_e8);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        uVar3 = FUN_100014b0(local_f0);
        FUN_100249f0(param_1,param_2,param_3,param_4,param_5,uVar3,param_7);
        FUN_10025060(param_1,param_2,param_3,iVar1);
        uVar4 = FUN_100243a0(param_1,param_2,iVar1);
        FUN_10024620(param_1,param_2,param_4 + (uVar4 & param_5) * 8,uVar4,param_3);
        *param_7 = *param_7 + -1;
      }
      FUN_10025060(param_1,param_2,param_3,local_648);
      if (local_648 == 0) {
        uVar4 = 0;
      }
      else {
        iVar1 = FUN_100013a0(param_1,(local_648 + -1) * param_2 + 0x224,&local_678,4,0);
        if (iVar1 == 4) {
          uVar4 = FUN_100014b0(local_678);
        }
        else {
          uVar4 = 0;
        }
      }
      FUN_10024620(param_1,param_2,param_4 + (uVar4 & param_5) * 8,uVar4,param_3);
      *param_7 = *param_7 + -1;
    }
    FUN_10025060(param_1,param_2,param_3,param_6);
    if (param_6 == 0) {
      local_680 = 0;
    }
    else {
      iVar1 = FUN_1002c3b0(param_1,(param_6 + -1) * param_2 + 0x224,&local_680,4,0);
      if (iVar1 != 4) {
        local_680 = 0;
      }
    }
    FUN_10024620(param_1,param_2,param_4 + (local_680 & param_5) * 8,local_680,param_3);
    *param_7 = *param_7 + -1;
  }
  return;
}

