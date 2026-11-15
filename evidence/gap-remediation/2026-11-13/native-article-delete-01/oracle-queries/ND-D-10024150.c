
void FUN_10024150(undefined4 param_1,int param_2,int *param_3,uint param_4,int param_5)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  byte abStack_420 [1032];
  
  iVar2 = param_2 * (*param_3 + -1) + 0x200;
  iVar5 = (param_4 - 1 >> 3) + iVar2;
  uVar4 = (iVar2 + (param_4 + param_5 + 7 >> 3)) - iVar5;
  if (0x400 < uVar4) {
    FUN_10027c30(1,0xb);
  }
  FUN_1002c3b0(param_1,iVar5,abStack_420,uVar4,0);
  uVar3 = param_4 - 1 & 7;
  while (bVar1 = param_5 != 0, param_5 = param_5 + -1, bVar1) {
    abStack_420[uVar3 >> 3] = abStack_420[uVar3 >> 3] & ~(byte)(1 << (7 - (uVar3 & 7) & 0x3f));
    uVar3 = uVar3 + 1;
  }
  FUN_1002c440(param_1,iVar5,abStack_420,uVar4,0);
  if (param_4 < (uint)param_3[2]) {
    param_3[2] = param_4;
    FUN_1002c440(param_1,0x3c,param_3,0xc,0);
  }
  return;
}

