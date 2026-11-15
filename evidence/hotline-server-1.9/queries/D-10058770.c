
void FUN_10058770(undefined4 *param_1)

{
  undefined4 local_20;
  undefined4 local_1c;
  
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  if (-1 < *(char *)(param_1 + 0x13)) {
    local_1c = 0;
    local_20 = 0x54525450;
    FUN_1006de90(*param_1,&local_20,8);
    *(byte *)(param_1 + 0x13) = *(byte *)(param_1 + 0x13) & 0x7f | 0x80;
  }
  return;
}

