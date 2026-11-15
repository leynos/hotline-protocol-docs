
void FUN_100073c0(int param_1,char *param_2,short *param_3)

{
  undefined4 uVar1;
  char cVar4;
  undefined4 uVar2;
  int iVar3;
  
  if (((*(int *)(param_1 + 0xb0) == 0) || (param_2 == (char *)0x0)) || (*param_2 == '\0')) {
    FUN_10027c30(4,0x66);
  }
  uVar1 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),0,param_2,800,0);
  cVar4 = FUN_1002ca10();
  if (cVar4 != '\0') {
    FUN_10027c30(4,0x66);
  }
  uVar2 = FUN_1002af80(uVar1,0,0x1008fed3,0x2a0,0);
  FUN_1002c220(uVar2,0x21);
  iVar3 = FUN_1002c3b0(uVar2,0,param_3,0x2de,0);
  if (iVar3 != 0x2de) {
    FUN_10027c30(1,8);
  }
  if (*param_3 != 1) {
    FUN_10027c30(1,7);
  }
  FUN_1002b2f0(uVar2);
  FUN_1002b2f0(uVar1);
  return;
}

