
void FUN_10058a70(undefined4 *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  uVar1 = FUN_10056d00(param_2);
  uVar2 = FUN_10053290();
  iVar3 = FUN_10052f80(uVar1);
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  iVar4 = param_1[3];
  if (iVar4 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(int *)(iVar4 + 8) == 0) {
    *(int *)(iVar4 + 8) = iVar3;
  }
  FUN_10058fd0(*param_1,*(undefined4 *)(iVar4 + 0x10),*(short *)(iVar4 + 0x1a) == 2,
               *(undefined2 *)(iVar4 + 0x18),*(undefined4 *)(iVar4 + 0x14),uVar2,iVar3,
               *(undefined4 *)(iVar4 + 8));
  *(int *)(iVar4 + 0xc) = *(int *)(iVar4 + 0xc) + iVar3;
  if ((param_1[1] != 0) && (*(uint *)(iVar4 + 8) <= *(uint *)(iVar4 + 0xc))) {
    FUN_1002a410(param_1[1],param_1[2],0);
  }
  FUN_10053310(uVar1);
  return;
}

