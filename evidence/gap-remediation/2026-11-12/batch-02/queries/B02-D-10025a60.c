
void FUN_10025a60(int param_1,int param_2,undefined4 param_3,char param_4)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined2 *puVar4;
  undefined1 *puVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  uint uVar9;
  
  uVar1 = 0x3f;
  if (*(byte *)(param_2 + 0x44) < 0x40) {
    uVar1 = (uint)*(byte *)(param_2 + 0x44);
  }
  uVar2 = 0x1f;
  if (*(byte *)(param_2 + 0x84) < 0x20) {
    uVar2 = (uint)*(byte *)(param_2 + 0x84);
  }
  uVar9 = 0;
  uVar7 = uVar1 + uVar2 + 0x18;
  if (param_4 != '\0') {
    uVar9 = 0x3f;
    if (*(byte *)(param_2 + 0xa4) < 0x40) {
      uVar9 = (uint)*(byte *)(param_2 + 0xa4);
    }
    uVar7 = uVar9 + uVar7 + 1;
  }
  if ((uint)(*(int *)(param_1 + 8) - (*(int *)(param_1 + 0x10) - *(int *)(param_1 + 4))) < uVar7) {
    FUN_10025e10(param_1);
  }
  uVar8 = *(undefined4 *)(param_2 + 0x24);
  puVar3 = *(undefined4 **)(param_1 + 0x10);
  *(undefined4 **)(param_1 + 0x10) = puVar3 + 1;
  *puVar3 = uVar8;
  puVar4 = *(undefined2 **)(param_1 + 0x10);
  *(undefined2 **)(param_1 + 0x10) = puVar4 + 4;
  *puVar4 = *(undefined2 *)(param_2 + 0x38);
  puVar4[1] = *(undefined2 *)(param_2 + 0x3a);
  *(undefined4 *)(puVar4 + 2) = *(undefined4 *)(param_2 + 0x3c);
  uVar8 = FUN_10025eb0(param_1,*(undefined4 *)(param_2 + 0x30));
  puVar3 = *(undefined4 **)(param_1 + 0x10);
  *(undefined4 **)(param_1 + 0x10) = puVar3 + 1;
  *puVar3 = uVar8;
  uVar8 = *(undefined4 *)(param_2 + 0x40);
  puVar3 = *(undefined4 **)(param_1 + 0x10);
  *(undefined4 **)(param_1 + 0x10) = puVar3 + 1;
  *puVar3 = uVar8;
  puVar4 = *(undefined2 **)(param_1 + 0x10);
  *(undefined2 **)(param_1 + 0x10) = puVar4 + 1;
  *(undefined2 **)(param_1 + 0x18) = puVar4;
  *puVar4 = 0;
  puVar5 = *(undefined1 **)(param_1 + 0x10);
  *(undefined1 **)(param_1 + 0x10) = puVar5 + 1;
  *puVar5 = (char)uVar1;
  iVar6 = FUN_100539c0(*(undefined4 *)(param_1 + 0x10),param_2 + 0x45,uVar1);
  puVar5 = (undefined1 *)(*(int *)(param_1 + 0x10) + iVar6);
  *(undefined1 **)(param_1 + 0x10) = puVar5 + 1;
  *puVar5 = (char)uVar2;
  iVar6 = FUN_100539c0(*(undefined4 *)(param_1 + 0x10),param_2 + 0x85,uVar2);
  *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + iVar6;
  if (param_4 != '\0') {
    puVar5 = *(undefined1 **)(param_1 + 0x10);
    *(undefined1 **)(param_1 + 0x10) = puVar5 + 1;
    *puVar5 = (char)uVar9;
    iVar6 = FUN_100539c0(*(undefined4 *)(param_1 + 0x10),param_2 + 0xa5,uVar9);
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + iVar6;
  }
  if (*(int *)(param_2 + 0x34) != 0) {
    FUN_10025f40(param_1,*(undefined4 *)(param_2 + 0x24),param_3);
  }
  *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
  return;
}

