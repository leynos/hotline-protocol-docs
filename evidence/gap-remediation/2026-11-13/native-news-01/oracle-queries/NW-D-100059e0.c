
undefined4 FUN_100059e0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined1 auStack_f0 [128];
  undefined4 local_30;
  int local_2c;
  undefined1 *local_14;
  
  local_2c = FUN_10023180(param_2,&local_30,0);
  if (local_2c == 0) {
    uVar1 = 0;
  }
  else {
    local_14 = auStack_f0 + 0x80;
    FUN_100568b0(param_3,0x141,local_2c,local_30);
    if (local_2c != 0) {
      FUN_10052c10(local_2c);
    }
    uVar1 = 1;
  }
  return uVar1;
}

