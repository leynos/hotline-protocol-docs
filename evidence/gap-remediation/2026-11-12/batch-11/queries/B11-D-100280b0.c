
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_100280b0(short param_1,short *param_2,short *param_3)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 1;
  iVar3 = 0x6c;
  do {
    iVar2 = iVar4 + iVar3 >> 1;
    psVar1 = (short *)(_DAT_100891a8 + iVar2 * 6 + -6);
    if (param_1 == *psVar1) {
      *param_2 = psVar1[1];
      *param_3 = psVar1[2];
      return;
    }
    if (param_1 < *psVar1) {
      iVar3 = iVar2 + -1;
    }
    if (*psVar1 <= param_1) {
      iVar4 = iVar2 + 1;
    }
  } while (iVar4 <= iVar3);
  *param_2 = 1;
  *param_3 = 1;
  return;
}

