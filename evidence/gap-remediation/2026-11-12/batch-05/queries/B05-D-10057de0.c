
void FUN_10057de0(undefined2 *param_1)

{
  undefined4 local_20 [7];
  
  .glue::GetDateTime(local_20);
  *param_1 = 0x770;
  param_1[1] = 0;
  *(undefined4 *)(param_1 + 2) = local_20[0];
  return;
}

