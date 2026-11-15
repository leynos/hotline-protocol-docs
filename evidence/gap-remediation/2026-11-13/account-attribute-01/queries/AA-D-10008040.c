
undefined4 FUN_10008040(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  char cVar3;
  undefined1 auStack_260 [32];
  undefined **local_240 [3];
  undefined4 local_234;
  undefined1 auStack_210 [512];
  
  FUN_1001fae0(local_240);
  uVar1 = FUN_10054180(auStack_210,0x200,s_The_Admin_account____s__does_not_1008feea,param_1 + 0x16c
                      );
  FUN_1003a450(local_234,0x10090035);
  FUN_10020090(local_240,param_1 + 0x16c,auStack_210,uVar1);
  FUN_1003a510(local_234,1);
  while( true ) {
    while( true ) {
      FUN_100370f0(local_240);
      iVar2 = FUN_100375d0(local_240);
      if (iVar2 != 1) break;
      cVar3 = FUN_100201c0(local_240,auStack_260);
      if (cVar3 != '\0') {
        uVar1 = FUN_10007780(param_1,param_1 + 0x16c,auStack_260,0);
        local_240[0] = &PTR_PTR_1008f1c0;
        FUN_10036850(local_240,0);
        return uVar1;
      }
    }
    if (iVar2 == 2) break;
    if (iVar2 == 10) {
      FUN_10020390(local_240);
    }
  }
  local_240[0] = &PTR_PTR_1008f1c0;
  FUN_10036850(local_240,0);
  return 0;
}

