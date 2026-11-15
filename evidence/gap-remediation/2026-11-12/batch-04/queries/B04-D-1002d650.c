
void FUN_1002d650(int param_1,int *param_2,uint param_3)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  ushort uVar4;
  int iVar5;
  
  if ((param_1 == 0) || (param_3 < 0x2a)) {
    FUN_10027c30(1,2);
  }
  if (*param_2 != 0x52464c54) {
    FUN_10027c30(1,8);
  }
  if (*(short *)(param_2 + 1) != 1) {
    FUN_10027c30(1,7);
  }
  FUN_1002d470(param_1);
  iVar5 = *(int *)(param_1 + 0x48);
  uVar1 = *(ushort *)(param_2 + 10);
  for (uVar4 = 0; uVar4 < uVar1; uVar4 = uVar4 + 1) {
    iVar2 = *(int *)((int)param_2 + (uint)uVar4 * 0x10 + 0x2a);
    if (iVar2 == 0x4d414352) {
      uVar3 = *(uint *)((int)param_2 + (uint)uVar4 * 0x10 + 0x2e);
      *(uint *)(iVar5 + 0xc) = uVar3;
      if (uVar3 < *(uint *)(iVar5 + 0x44)) {
        *(int *)(iVar5 + 0x44) = *(int *)(iVar5 + 0x44) - *(int *)(iVar5 + 0xc);
      }
      else {
        *(undefined4 *)(iVar5 + 0x44) = 0;
      }
    }
    else if ((iVar2 < 0x4d414352) && (iVar2 == 0x44415441)) {
      uVar3 = *(uint *)((int)param_2 + (uint)uVar4 * 0x10 + 0x2e);
      *(uint *)(iVar5 + 8) = uVar3;
      if (uVar3 < *(uint *)(iVar5 + 0x34)) {
        *(int *)(iVar5 + 0x34) = *(int *)(iVar5 + 0x34) - *(int *)(iVar5 + 8);
      }
      else {
        *(undefined4 *)(iVar5 + 0x34) = 0;
      }
    }
  }
  return;
}

