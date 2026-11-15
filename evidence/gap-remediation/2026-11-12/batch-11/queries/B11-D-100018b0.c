
void FUN_100018b0(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_3 + 4);
  if (iVar1 == 0x6a) {
    FUN_100023a0(param_1);
  }
  else if (iVar1 < 0x6a) {
    if (iVar1 == 0x66) {
      FUN_10003f30(param_1);
      FUN_10003940(param_1,1);
    }
    else if (iVar1 < 0x66) {
      if (iVar1 == 100) {
        FUN_10002dd0(param_1);
      }
      else if (99 < iVar1) {
        FUN_10003170(param_1);
      }
    }
    else if (iVar1 == 0x68) {
      FUN_10002350(param_1);
    }
    else if (iVar1 < 0x68) {
      FUN_10002300(param_1);
    }
    else {
      FUN_10082630(param_1);
    }
  }
  else if (iVar1 == 0x6d) {
    if (*(int *)(param_1 + 0x94) != 0) {
      FUN_1001ecb0(*(undefined4 *)(param_1 + 0x94));
    }
  }
  else if (iVar1 < 0x6d) {
    if (iVar1 < 0x6c) {
      FUN_10082630(param_1);
    }
    else {
      FUN_10003640(param_1);
    }
  }
  else if (iVar1 == 0x77696e64) {
    FUN_10003680(param_1);
  }
  return;
}

