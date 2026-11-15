
undefined4 FUN_10018fd0(int param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined1 local_90;
  undefined1 auStack_8f [63];
  byte local_50;
  undefined1 auStack_4f [67];
  
  if (*(int *)(param_1 + 0x78) == 0) {
    uVar1 = 0;
  }
  else {
    local_90 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x70) + 0x2c),auStack_8f,0x3f);
    FUN_100691c0(*(undefined4 *)(param_1 + 0x70),0,0);
    local_50 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x74) + 0x2c),auStack_4f,0x3f);
    FUN_100691c0(*(undefined4 *)(param_1 + 0x74),0,0);
    uVar4 = *(uint *)(param_1 + 0x78);
    *(undefined4 *)(param_1 + 0x78) = 0;
    uVar2 = FUN_10082630(param_1);
    if (uVar2 < uVar4) {
      uVar1 = 0;
    }
    else {
      iVar3 = FUN_1001b000(param_1,uVar4);
      if (iVar3 == 0) {
        uVar1 = 0;
      }
      else {
        FUN_10009990(iVar3,&local_90);
        FUN_100539c0(iVar3 + 0x31,&local_50,local_50 + 1);
        FUN_10069f70(param_1,uVar4);
        uVar1 = 1;
      }
    }
  }
  return uVar1;
}

