
void FUN_10006e80(int param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  short local_520 [2];
  undefined4 local_51c;
  undefined1 local_518;
  undefined1 auStack_517 [127];
  undefined1 local_498;
  undefined1 auStack_497 [127];
  undefined1 local_418;
  undefined1 auStack_417 [1039];
  
  if ((*(uint *)(param_1 + 0xac) & 8) != 0) {
    local_518 = FUN_10057e30(auStack_517,0x7f,0x22);
    uVar1 = FUN_10058270(*(undefined4 *)(param_2 + 4));
    local_498 = FUN_1006d550(uVar1,auStack_497,0x7f);
    local_418 = FUN_10054180(auStack_417,0x3ff,s__Date_time_Address_Account_Name_F_1008fe27 + 0x2a,
                             &local_518,&local_498,param_2 + 0x78,param_2 + 0x38);
    local_51c = FUN_1002af80(0xfffffffe,0,PTR_DAT_1008ee34,0x280,local_520);
    if (local_520[0] == 1) {
      FUN_1002b370(local_51c,0x54455854,0x74747874);
    }
    FUN_1002c220(local_51c,0x23);
    uVar2 = FUN_1002c4d0(local_51c,0);
    if (uVar2 == 0) {
      uVar2 = (uint)bRam1008fe62;
      FUN_1002c440(local_51c,0,s_Date_time_Address_Account_Name___1008fe63,uVar2,0);
    }
    FUN_1002c440(local_51c,uVar2,auStack_417,local_418,0);
    FUN_1002b2f0(local_51c);
  }
  return;
}

