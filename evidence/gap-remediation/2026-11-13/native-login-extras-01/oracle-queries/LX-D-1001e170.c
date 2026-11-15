
void FUN_1001e170(int param_1,undefined1 *param_2,undefined1 *param_3,undefined4 param_4,
                 undefined1 *param_5,undefined1 *param_6,undefined1 *param_7,undefined4 param_8)

{
  uint uVar1;
  undefined1 uVar3;
  int iVar2;
  undefined4 *in_stack_00000038;
  undefined1 auStack_14f [31];
  undefined1 local_130;
  undefined1 auStack_12f [267];
  
  if (param_2 != (undefined1 *)0x0) {
    uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x20) + 0x2c),param_2 + 1,0x1f);
    *param_2 = uVar3;
  }
  if (param_3 != (undefined1 *)0x0) {
    uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x24) + 0x2c),param_3 + 1,0x7f);
    *param_3 = uVar3;
  }
  if (param_5 != (undefined1 *)0x0) {
    uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0xac) + 0x2c),param_5 + 1,0x7f);
    *param_5 = uVar3;
  }
  if (param_6 != (undefined1 *)0x0) {
    uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0xb0) + 0x2c),param_6 + 1,0xff);
    *param_6 = uVar3;
  }
  if (param_7 != (undefined1 *)0x0) {
    local_130 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0xb4) + 0x2c),auStack_12f,0xff);
    uVar3 = FUN_1006d670(0x2a,auStack_12f,local_130,param_7 + 1,0xff);
    *param_7 = uVar3;
  }
  FUN_1001e7a0(param_1,param_4);
  *in_stack_00000038 = 0;
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x40) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((-1 < iVar2) && (iVar2 < 0x100)) {
    *(char *)in_stack_00000038 = (char)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x44) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((-1 < iVar2) && (iVar2 < 0x100)) {
    *(char *)((int)in_stack_00000038 + 1) = (char)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x48) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((-1 < iVar2) && (iVar2 < 0x100)) {
    *(char *)((int)in_stack_00000038 + 2) = (char)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x4c) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((-1 < iVar2) && (iVar2 < 0x100)) {
    *(char *)((int)in_stack_00000038 + 3) = (char)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x3c) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((0 < iVar2) && (iVar2 < 0xffff)) {
    *(short *)(in_stack_00000038 + 1) = (short)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x30) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((0 < iVar2) && (iVar2 < 0xffff)) {
    *(short *)(in_stack_00000038 + 2) = (short)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x34) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((0 < iVar2) && (iVar2 < 0xffff)) {
    *(short *)((int)in_stack_00000038 + 10) = (short)iVar2;
  }
  uVar3 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x38) + 0x2c),auStack_14f,0x1f);
  iVar2 = FUN_10054000(auStack_14f,uVar3,0,0);
  if ((-1 < iVar2) && (iVar2 < 0xffff)) {
    *(short *)(in_stack_00000038 + 3) = (short)iVar2;
  }
  uVar1 = (uint)(*(char *)(*(int *)(param_1 + 0x50) + 0x39) != '\0');
  if (*(char *)(*(int *)(param_1 + 0x54) + 0x39) != '\0') {
    uVar1 = uVar1 | 2;
  }
  if (*(char *)(*(int *)(param_1 + 0x58) + 0x39) != '\0') {
    uVar1 = uVar1 | 4;
  }
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0x39) != '\0') {
    uVar1 = uVar1 | 8;
  }
  if (*(char *)(*(int *)(param_1 + 0x6c) + 0x39) != '\0') {
    uVar1 = uVar1 | 0x40;
  }
  if (*(char *)(*(int *)(param_1 + 0x60) + 0x39) != '\0') {
    uVar1 = uVar1 | 0x10;
  }
  if (*(char *)(*(int *)(param_1 + 100) + 0x39) != '\0') {
    uVar1 = uVar1 | 0x20;
  }
  if (*(char *)(*(int *)(param_1 + 0x68) + 0x39) != '\0') {
    uVar1 = uVar1 | 0x100;
  }
  if (*(char *)(*(int *)(param_1 + 0xb8) + 0x39) != '\0') {
    uVar1 = uVar1 | 0x80;
  }
  in_stack_00000038[4] = uVar1;
  FUN_10018fd0(*(undefined4 *)(param_1 + 0x74));
  FUN_10022450(*(undefined4 *)(param_1 + 0x74),param_8);
  return;
}

