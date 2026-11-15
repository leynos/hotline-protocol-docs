
void FUN_100587f0(undefined4 *param_1,int param_2)

{
  undefined4 local_20;
  int local_1c;
  
  if ((param_1 == (undefined4 *)0x0) || (*(char *)(param_1 + 0x13) < '\0')) {
    FUN_10027c30(1,2);
  }
  if (param_2 == 0) {
    param_2 = 1;
  }
  local_20 = 0x54525450;
  local_1c = param_2;
  FUN_1006de90(*param_1,&local_20,8);
  return;
}

