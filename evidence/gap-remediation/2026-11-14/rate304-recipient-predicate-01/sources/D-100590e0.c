
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_100590e0(undefined4 *param_1)

{
  int iVar1;
  char cVar5;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar6;
  int *piVar7;
  short sVar8;
  undefined4 uVar9;
  int *piVar10;
  int *piVar11;
  int *piVar12;
  
  if ((-1 < *(char *)(param_1 + 0x13)) || ((*(byte *)(param_1 + 0x13) >> 4 & 1) != 0)) {
    return;
  }
  uVar9 = *param_1;
  piVar11 = param_1 + 6;
  piVar10 = param_1 + 7;
  piVar12 = param_1 + 8;
  do {
    while (*piVar11 == 0) {
      cVar5 = FUN_1006e120(uVar9,0x14);
      if (cVar5 == '\0') {
        return;
      }
      iVar2 = FUN_1006dfb0(uVar9,param_1 + 9,0x14);
      if (iVar2 == 0) {
        return;
      }
      if ((((param_1[0xc] == 0) || (_DAT_10094a50 < (uint)param_1[0xc])) || (param_1[0xd] == 0)) ||
         (_DAT_10094a50 < (uint)param_1[0xd])) {
        *(byte *)(param_1 + 0x13) = *(byte *)(param_1 + 0x13) & 0xef | 0x10;
        FUN_1006daf0(uVar9);
        return;
      }
      if (*piVar12 == 0) {
        iVar2 = FUN_10052c50(param_1[0xd],0);
        *piVar12 = iVar2;
      }
      else {
        FUN_10053130(*piVar12,param_1[0xd]);
      }
      *piVar11 = param_1[0xd];
      *piVar10 = 0;
    }
    iVar2 = *piVar12;
    iVar3 = FUN_10053290();
    iVar4 = FUN_1006dfb0(uVar9,iVar3 + *piVar10,*piVar11);
    if (iVar4 == 0) {
      FUN_10053310(iVar2);
      return;
    }
    *piVar10 = *piVar10 + iVar4;
    iVar1 = *piVar11;
    *piVar11 = iVar1 - iVar4;
    if (iVar1 - iVar4 == 0) {
      sVar8 = 3;
      if (*(char *)((int)param_1 + 0x25) != '\0') {
        sVar8 = 4;
      }
      for (puVar6 = (undefined4 *)param_1[4]; puVar6 != (undefined4 *)0x0;
          puVar6 = (undefined4 *)*puVar6) {
        if ((*(short *)((int)puVar6 + 0x1a) == sVar8) && (puVar6[4] == param_1[10]))
        goto LAB_10059370;
      }
      puVar6 = (undefined4 *)0x0;
LAB_10059370:
      iVar4 = FUN_10052f80(*piVar12);
      if (puVar6 == (undefined4 *)0x0) {
        if (*(char *)((int)param_1 + 0x25) == '\0') {
          iVar3 = FUN_10052b70(0x20);
          piVar7 = (int *)param_1[4];
          if (piVar7 == (int *)0x0) {
            param_1[4] = iVar3;
          }
          else {
            for (; *piVar7 != 0; piVar7 = (int *)*piVar7) {
            }
            *piVar7 = iVar3;
          }
          *(undefined2 *)(iVar3 + 0x1a) = 3;
          *(undefined2 *)(iVar3 + 0x18) = *(undefined2 *)((int)param_1 + 0x26);
          *(undefined4 *)(iVar3 + 0x10) = param_1[10];
          *(undefined4 *)(iVar3 + 8) = param_1[0xc];
          *(int *)(iVar3 + 0xc) = iVar4;
          *(int *)(iVar3 + 4) = *piVar12;
          *piVar12 = 0;
        }
      }
      else {
        puVar6[5] = param_1[0xb];
        *(undefined2 *)(puVar6 + 6) = *(undefined2 *)((int)param_1 + 0x26);
        puVar6[2] = param_1[0xc];
        *(byte *)(puVar6 + 7) = *(byte *)(puVar6 + 7) & 0xdf | 0x20;
        if (puVar6[1] == 0) {
          puVar6[1] = *piVar12;
          *piVar12 = 0;
        }
        else {
          FUN_10053440(puVar6[1],iVar3,iVar4);
        }
        puVar6[3] = puVar6[3] + iVar4;
      }
    }
    else if (*(char *)((int)param_1 + 0x25) != '\0') {
      for (puVar6 = (undefined4 *)param_1[4]; puVar6 != (undefined4 *)0x0;
          puVar6 = (undefined4 *)*puVar6) {
        if ((*(short *)((int)puVar6 + 0x1a) == 4) && (puVar6[4] == param_1[10])) goto LAB_10059300;
      }
      puVar6 = (undefined4 *)0x0;
LAB_10059300:
      if (puVar6 != (undefined4 *)0x0) {
        puVar6[3] = puVar6[3] + iVar4;
        puVar6[2] = param_1[0xc];
      }
    }
    FUN_10053310(iVar2);
  } while( true );
}

