
void FUN_10004930(int param_1,int param_2)

{
  undefined2 uVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  
  if (param_2 != 0) {
    uVar1 = *(undefined2 *)(param_2 + 0x14);
    FUN_10055b20(param_1 + 0x34,param_2);
    uVar4 = *(undefined4 *)(param_2 + 4);
    FUN_1006d290(param_2);
    FUN_10058160(uVar4);
    *(int *)(param_1 + 0x428) = *(int *)(param_1 + 0x428) + -1;
    uVar4 = FUN_10056380(0,0);
    puVar9 = *(undefined4 **)(param_1 + 0x420);
    while (puVar9 != (undefined4 *)0x0) {
      iVar2 = FUN_10055630(puVar9 + 1,param_2);
      if (iVar2 != 0) {
        FUN_10056820(uVar4);
        FUN_10056a90(uVar4,0x72,puVar9[4]);
        FUN_10056a90(uVar4,0x67,uVar1);
        iVar2 = puVar9[1];
        iVar6 = puVar9[2];
        for (iVar7 = 0; iVar7 != iVar6; iVar7 = iVar7 + 1) {
          iVar8 = *(int *)(iVar2 + iVar7 * 4);
          cVar3 = FUN_10058600(*(undefined4 *)(iVar8 + 4));
          if (cVar3 != '\0') {
            FUN_10058ca0(*(undefined4 *)(iVar8 + 4),0x76,uVar4);
          }
        }
      }
      if (puVar9[2] == 0) {
        puVar5 = (undefined4 *)*puVar9;
        FUN_10055b20(param_1 + 0x420,puVar9);
        FUN_10052c10(puVar9[5]);
        if (puVar9 != (undefined4 *)0x0) {
          if (puVar9 != (undefined4 *)0xfffffffc) {
            FUN_10055480(puVar9 + 1,0);
          }
          FUN_1006d290(puVar9);
        }
        puVar9 = puVar5;
      }
      else {
        puVar9 = (undefined4 *)*puVar9;
      }
    }
    FUN_100563d0(uVar4);
    uVar4 = FUN_10056380(0,0);
    FUN_10056a90(uVar4,0x67,uVar1);
    FUN_10005510(param_1,0x12e,uVar4);
    FUN_10057940(0,0x81,1);
    if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
      *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
    }
    if (*(int *)(param_1 + 0x8c) != 0) {
      FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                   *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                   *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                   *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                   *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
    }
    FUN_100563d0(uVar4);
  }
  return;
}

