
void FUN_1006e620(undefined4 param_1,int *param_2,undefined4 param_3)

{
  bool bVar1;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  
  FUN_10033260(param_1,&local_30);
  bVar1 = false;
  if (local_30 == 0) {
    if (local_2c == 0) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    FUN_1004bb90(param_1,param_2,param_3);
  }
  else {
    FUN_100332b0(param_1);
    local_28 = *param_2 - local_30;
    local_24 = param_2[1] - local_2c;
    local_20 = param_2[2] - local_30;
    local_1c = param_2[3] - local_2c;
    FUN_1004bb90(param_1,&local_28,param_3);
    FUN_10033240(param_1,&local_30);
  }
  return;
}

