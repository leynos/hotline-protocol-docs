
void FUN_1002b670(int param_1)

{
  undefined4 uVar1;
  undefined4 local_20 [7];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  uVar1 = .glue::FSpDirCreate(param_1,0,local_20);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  *(undefined4 *)(param_1 + 2) = local_20[0];
  *(undefined1 *)(param_1 + 6) = 0;
  return;
}

