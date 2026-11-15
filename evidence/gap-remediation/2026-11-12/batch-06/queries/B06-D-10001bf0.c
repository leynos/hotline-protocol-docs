
void FUN_10001bf0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined **local_128 [3];
  undefined4 local_11c;
  int local_114;
  byte local_110;
  undefined1 auStack_10f [263];
  
  if ((*(int *)(param_1 + 0x34) == 0) || ((*(uint *)(param_1 + 0xac) & 0x20) == 0)) {
    FUN_10082630(param_1);
  }
  else {
    FUN_10021eb0(local_128);
    FUN_100578e0();
    FUN_1003a510(local_11c,1);
    do {
      FUN_100370f0(local_128);
      iVar1 = FUN_100375d0(local_128);
      if (iVar1 == 1) {
        if (*(int *)(param_1 + 0x34) == 0) {
          FUN_10082630(param_1);
        }
        else {
          FUN_10057380(4);
          *(byte *)(param_1 + 200) = *(byte *)(param_1 + 200) & 0x7f | 0x80;
          local_110 = FUN_10042f80(*(undefined4 *)(local_114 + 0x2c),auStack_10f,0xff);
          if (local_110 == 0) {
            FUN_10082630(param_1);
            local_128[0] = &PTR_PTR_1008f748;
            FUN_10036850(local_128,0);
            return;
          }
          uVar2 = FUN_10056380(0,0);
          FUN_10056ae0(uVar2,0x65,&local_110);
          FUN_10005510(param_1,0x6f,uVar2);
          FUN_10057380(0);
          FUN_10005bf0(param_1);
          FUN_100563d0(uVar2);
        }
        break;
      }
      if (iVar1 == 2) {
        FUN_10082630(param_1);
        break;
      }
    } while (iVar1 != 3);
    local_128[0] = &PTR_PTR_1008f748;
    FUN_10036850(local_128,0);
  }
  return;
}

