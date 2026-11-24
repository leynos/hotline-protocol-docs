
void FUN_10056a90(undefined4 param_1,undefined4 param_2,uint param_3)

{
  undefined2 local_10 [2];
  uint local_c [3];
  
  if ((param_3 & 0xffff0000) == 0) {
    local_10[0] = (undefined2)param_3;
    FUN_100568b0(param_1,param_2,local_10,2);
  }
  else {
    local_c[0] = param_3;
    FUN_100568b0(param_1,param_2,local_c,4);
  }
  return;
}

