
void FUN_1002c220(int param_1,short param_2)

{
  undefined4 uVar1;
  undefined2 local_20 [12];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(short *)(param_1 + 0x50) != 0) {
    FUN_10027c30(1,3);
  }
  uVar1 = FUN_1007fc50(param_1,(int)param_2,local_20);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  *(undefined2 *)(param_1 + 0x50) = local_20[0];
  return;
}

