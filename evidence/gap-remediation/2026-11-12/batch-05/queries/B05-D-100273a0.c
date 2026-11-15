
int FUN_100273a0(int *param_1,int *param_2,short *param_3,short *param_4,undefined1 *param_5)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  byte local_120 [260];
  
  if (param_1[2] == 0) {
    param_1[2] = param_1[2] + 1;
    *param_5 = 1;
    FUN_1002bce0(*param_1,local_120,0);
    if (*param_3 < (short)(local_120[0] + 3)) {
      *param_3 = -1;
    }
    else {
      *param_3 = *param_3 - (local_120[0] + 3);
      iVar2 = *param_2 - (local_120[0] + 1);
      *param_2 = iVar2;
      FUN_1007c240(iVar2,local_120);
      iVar2 = *param_2;
      *param_2 = iVar2 + -2;
      *(undefined2 *)(iVar2 + -2) = 0;
      *param_4 = *param_4 + 1;
    }
    iVar2 = *param_1;
  }
  else {
    iVar2 = param_1[4];
    while (param_1[2] != iVar2 + 1) {
      uVar5 = param_1[2];
      bVar1 = false;
      if ((uVar5 != 0) && (uVar5 <= (uint)param_1[4])) {
        bVar1 = true;
      }
      if (bVar1) {
        uVar3 = *(undefined4 *)(param_1[3] + uVar5 * 4 + -4);
      }
      else {
        uVar3 = 0;
      }
      iVar4 = FUN_100262e0(uVar3,param_2,param_3,param_4,param_5);
      if (iVar4 != 0) {
        FUN_1002bce0(*param_1,local_120,0);
        if (*param_3 < (short)(local_120[0] + 3)) {
          *param_3 = -1;
        }
        else {
          *param_3 = *param_3 - (local_120[0] + 3);
          iVar2 = *param_2 - (local_120[0] + 1);
          *param_2 = iVar2;
          FUN_1007c240(iVar2,local_120);
          iVar2 = *param_2;
          *param_2 = iVar2 + -2;
          *(undefined2 *)(iVar2 + -2) = 0;
          *param_4 = *param_4 + 1;
        }
        return iVar4;
      }
      param_1[2] = param_1[2] + 1;
    }
    iVar2 = 0;
  }
  return iVar2;
}

