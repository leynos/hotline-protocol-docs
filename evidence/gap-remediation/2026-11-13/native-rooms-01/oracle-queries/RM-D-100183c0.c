
void FUN_100183c0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined2 uVar6;
  int iVar7;
  int iVar8;
  undefined2 local_228;
  undefined2 local_226;
  undefined2 local_224;
  ushort local_222;
  undefined1 auStack_220 [512];
  
  uVar2 = FUN_10056b90(param_4,0x72);
  iVar3 = FUN_10004760(param_1,uVar2);
  if (iVar3 == 0) {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,s_<Cannot_join_private_chat_becaus_10092214);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    uVar4 = FUN_10056380(0,0);
    iVar5 = FUN_1006cf30(param_2,*(undefined4 *)(iVar3 + 4),*(undefined4 *)(iVar3 + 8));
    if (iVar5 == 0) {
      FUN_10056a90(uVar4,0x72,uVar2);
      FUN_10056a90(uVar4,0x67,*(undefined2 *)(param_2 + 0x14));
      FUN_10056a90(uVar4,0x68,(int)*(short *)(param_2 + 0x16));
      uVar6 = FUN_10005000(param_1,param_2);
      FUN_10056a90(uVar4,0x70,uVar6);
      FUN_10056ae0(uVar4,0x66,param_2 + 0x38);
      FUN_100048b0(param_1,iVar3,0x75,uVar4);
      FUN_100554e0(iVar3 + 4,param_2);
    }
    iVar5 = *(int *)(iVar3 + 4);
    iVar8 = *(int *)(iVar3 + 8);
    FUN_10056820(uVar4);
    if (*(int *)(iVar3 + 0x14) != 0) {
      FUN_10056ae0(uVar4,0x73,*(undefined4 *)(iVar3 + 0x14));
    }
    for (iVar3 = 0; iVar3 != iVar8; iVar3 = iVar3 + 1) {
      iVar7 = *(int *)(iVar5 + iVar3 * 4);
      local_228 = *(undefined2 *)(iVar7 + 0x14);
      local_226 = *(undefined2 *)(iVar7 + 0x16);
      local_224 = FUN_10005000(param_1,iVar7);
      bVar1 = *(byte *)(iVar7 + 0x38);
      FUN_100539c0(auStack_220,iVar7 + 0x39,(uint)bVar1);
      local_222 = (ushort)bVar1;
      if (bVar1 != 0) {
        FUN_100568b0(uVar4,300,&local_228,bVar1 + 8);
      }
    }
    FUN_10058a70(param_3,uVar4);
    FUN_100563d0(uVar4);
  }
  return;
}

