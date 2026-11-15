
void FUN_10012f40(int param_1,int param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  uVar1 = FUN_10056380(0,0);
  iVar2 = FUN_10052b70(0x18);
  uVar3 = FUN_100046c0(param_1);
  *(uint *)(iVar2 + 4) = uVar3 | 1;
  uVar4 = FUN_10057d00();
  *(undefined4 *)(iVar2 + 8) = uVar4;
  *(int *)(iVar2 + 0x10) = param_2;
  *(undefined2 *)(iVar2 + 0x14) = *(undefined2 *)(param_2 + 0x14);
  FUN_100554e0(param_1 + 0x5c,iVar2);
  uVar4 = FUN_10052f80(*(undefined4 *)(param_1 + 0xc));
  FUN_10056a90(uVar1,0x6c,uVar4);
  FUN_100568b0(uVar1,0x6b,iVar2 + 4,4);
  FUN_10058a70(param_3,uVar1);
  FUN_100563d0(uVar1);
  return;
}

