
undefined4
FUN_10005ac0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  int iVar1;
  undefined4 local_e0 [2];
  undefined1 auStack_d8 [4];
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined1 auStack_c0 [8];
  undefined1 auStack_b8 [64];
  undefined1 auStack_78 [108];
  
  iVar1 = FUN_100233e0(param_2,param_3,param_4,local_e0,auStack_d8);
  if (iVar1 != 0) {
    FUN_100568b0(param_5,0x14d,iVar1,local_e0[0]);
    FUN_10052c10(iVar1);
  }
  FUN_10056a90(param_5,0x14b,local_d4);
  FUN_10056a90(param_5,0x14c,local_d0);
  FUN_10056a90(param_5,0x14f,local_cc);
  FUN_10056a90(param_5,0x150,local_c8);
  FUN_10056ae0(param_5,0x148,auStack_b8);
  FUN_10056ae0(param_5,0x149,auStack_78);
  FUN_10056b10(param_5,0x147,param_4);
  FUN_100568b0(param_5,0x14a,auStack_c0,8);
  return 1;
}

