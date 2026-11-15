
void FUN_10025c60(int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  undefined1 *puVar3;
  int iVar4;
  undefined2 *puVar5;
  
  if (*(uint *)(param_1 + 8) < (uint)(*(int *)(param_1 + 0x10) - *(int *)(param_1 + 4))) {
    FUN_10001bd0(s_ptr_advanced_too_far__100938bc);
  }
  if (*(int *)(param_1 + 0x18) == 0) {
    FUN_10027c30(1,2);
  }
  uVar1 = 0x3f;
  if (*(byte *)(param_2 + 8) < 0x40) {
    uVar1 = (uint)*(byte *)(param_2 + 8);
  }
  if ((uint)(*(int *)(param_1 + 8) - (*(int *)(param_1 + 0x10) - *(int *)(param_1 + 4))) < uVar1 + 3
     ) {
    FUN_10025e10(param_1);
  }
  puVar3 = *(undefined1 **)(param_1 + 0x10);
  *(undefined1 **)(param_1 + 0x10) = puVar3 + 1;
  *puVar3 = (char)uVar1;
  iVar4 = FUN_100539c0(*(undefined4 *)(param_1 + 0x10),param_2 + 9,uVar1);
  puVar5 = (undefined2 *)(*(int *)(param_1 + 0x10) + iVar4);
  *(undefined2 **)(param_1 + 0x10) = puVar5;
  uVar2 = *(undefined4 *)(param_2 + 4);
  *(undefined2 **)(param_1 + 0x10) = puVar5 + 1;
  *puVar5 = (short)uVar2;
  **(short **)(param_1 + 0x18) = **(short **)(param_1 + 0x18) + 1;
  return;
}

