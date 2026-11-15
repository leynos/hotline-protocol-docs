
int FUN_1002c4d0(int param_1,uint param_2)

{
  undefined4 uVar1;
  int local_20;
  int local_1c [5];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(short *)(param_1 + 0x50) == 0) {
    uVar1 = FUN_1007f9e0(param_1,&local_20,local_1c);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
    if ((param_2 & 1) == 0) {
      local_20 = local_20 + local_1c[0];
    }
  }
  else {
    uVar1 = .glue::GetEOF((int)*(short *)(param_1 + 0x50),&local_20);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
  }
  return local_20;
}

