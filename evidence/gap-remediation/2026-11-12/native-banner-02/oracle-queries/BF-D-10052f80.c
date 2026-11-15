
uint FUN_10052f80(int *param_1)

{
  uint uVar1;
  int iVar2;
  
  if (param_1 == (int *)0x0) {
    FUN_10027c30(1,2);
  }
  if (*param_1 == 0) {
    uVar1 = 0;
  }
  else {
    iVar2 = .glue::GetHandleSize(param_1);
    uVar1 = iVar2 - 4U & ~-(uint)(iVar2 == 0);
  }
  return uVar1;
}

