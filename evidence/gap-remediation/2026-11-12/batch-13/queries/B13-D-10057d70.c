
void FUN_10057d70(int param_1,int param_2)

{
  undefined4 local_20 [7];
  
  if (param_1 != 1) {
    FUN_10027c30(1,2);
  }
  .glue::GetDateTime(local_20);
  .glue::SecondsToDate(local_20[0],param_2);
  *(undefined2 *)(param_2 + 0xe) = 0;
  return;
}

