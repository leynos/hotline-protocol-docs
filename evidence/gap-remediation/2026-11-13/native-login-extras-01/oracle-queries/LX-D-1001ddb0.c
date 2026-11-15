
void FUN_1001ddb0(int param_1,undefined1 *param_2,undefined1 *param_3,undefined4 param_4,
                 undefined1 *param_5,undefined1 *param_6,undefined1 *param_7,undefined4 param_8)

{
  undefined1 uVar1;
  undefined1 *in_stack_00000038;
  undefined1 auStack_3f [31];
  
  if (param_2 != (undefined1 *)0x0) {
    FUN_100691c0(*(undefined4 *)(param_1 + 0x20),param_2 + 1,*param_2);
  }
  if (param_3 != (undefined1 *)0x0) {
    FUN_100691c0(*(undefined4 *)(param_1 + 0x24),param_3 + 1,*param_3);
  }
  if (param_5 != (undefined1 *)0x0) {
    FUN_100691c0(*(undefined4 *)(param_1 + 0xac),param_5 + 1,*param_5);
  }
  if (param_6 != (undefined1 *)0x0) {
    FUN_100691c0(*(undefined4 *)(param_1 + 0xb0),param_6 + 1,*param_6);
  }
  if (param_7 != (undefined1 *)0x0) {
    FUN_100691c0(*(undefined4 *)(param_1 + 0xb4),param_7 + 1,*param_7);
  }
  FUN_1001e730(param_1,param_4);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,*in_stack_00000038,0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x40),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,in_stack_00000038[1],0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x44),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,in_stack_00000038[2],0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x48),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,in_stack_00000038[3],0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x4c),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,*(undefined2 *)(in_stack_00000038 + 4),0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x3c),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,*(undefined2 *)(in_stack_00000038 + 8),0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x30),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,*(undefined2 *)(in_stack_00000038 + 10),0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x34),auStack_3f,uVar1);
  uVar1 = FUN_10053c10(auStack_3f,0x1f,*(undefined2 *)(in_stack_00000038 + 0xc),0);
  FUN_100691c0(*(undefined4 *)(param_1 + 0x38),auStack_3f,uVar1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x50),*(uint *)(in_stack_00000038 + 0x10) & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x54),*(uint *)(in_stack_00000038 + 0x10) >> 1 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x58),*(uint *)(in_stack_00000038 + 0x10) >> 2 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x5c),*(uint *)(in_stack_00000038 + 0x10) >> 3 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x6c),*(uint *)(in_stack_00000038 + 0x10) >> 6 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x60),*(uint *)(in_stack_00000038 + 0x10) >> 4 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 100),*(uint *)(in_stack_00000038 + 0x10) >> 5 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0x68),*(uint *)(in_stack_00000038 + 0x10) >> 8 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0xb8),*(uint *)(in_stack_00000038 + 0x10) >> 7 & 1);
  FUN_10082630(*(undefined4 *)(param_1 + 0xbc),*(uint *)(in_stack_00000038 + 0x10) >> 7 & 1 ^ 1);
  FUN_1001e600(param_1);
  FUN_10022580(*(undefined4 *)(param_1 + 0x74),param_8);
  return;
}

