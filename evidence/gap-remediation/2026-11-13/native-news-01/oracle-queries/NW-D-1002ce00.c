
undefined4
FUN_1002ce00(int param_1,int *param_2,int param_3,undefined4 *param_4,undefined4 *param_5,
            undefined4 *param_6,undefined2 *param_7,undefined2 *param_8)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 *in_stack_00000038;
  
  if (param_1 == 0) {
    uVar1 = 0;
  }
  else {
    iVar2 = FUN_10053290(param_1);
    uVar3 = FUN_10052f80(param_1);
    if (*param_2 == 0) {
      *param_2 = 4;
    }
    if (uVar3 < *param_2 + 0x24U) {
      FUN_10053310(param_1);
      uVar1 = 0;
    }
    else {
      puVar4 = (undefined4 *)(iVar2 + *param_2);
      if (param_3 != 0) {
        .glue::BlockMoveData(puVar4 + 9,param_3,*(byte *)(puVar4 + 9) + 1);
      }
      if (param_4 != (undefined4 *)0x0) {
        *param_4 = *puVar4;
      }
      if (param_5 != (undefined4 *)0x0) {
        *param_5 = puVar4[1];
      }
      if (param_6 != (undefined4 *)0x0) {
        *param_6 = puVar4[2];
      }
      if (param_7 != (undefined2 *)0x0) {
        *param_7 = *(undefined2 *)(puVar4 + 5);
        param_7[1] = *(undefined2 *)((int)puVar4 + 0x16);
        *(undefined4 *)(param_7 + 2) = puVar4[6];
      }
      if (param_8 != (undefined2 *)0x0) {
        *param_8 = *(undefined2 *)(puVar4 + 7);
        param_8[1] = *(undefined2 *)((int)puVar4 + 0x1e);
        *(undefined4 *)(param_8 + 2) = puVar4[8];
      }
      if (in_stack_00000038 != (undefined4 *)0x0) {
        *in_stack_00000038 = puVar4[3];
      }
      *param_2 = *param_2 + (*(byte *)(puVar4 + 9) + 0x28 & 0xfffffffc);
      FUN_10053310(param_1);
      uVar1 = 1;
    }
  }
  return uVar1;
}

