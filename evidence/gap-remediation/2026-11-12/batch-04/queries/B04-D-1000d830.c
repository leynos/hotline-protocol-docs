
void FUN_1000d830(int param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined1 auStack_120 [128];
  undefined4 local_5c;
  int local_58 [7];
  undefined1 *local_3c;
  undefined1 *local_24;
  
  local_5c = 0;
  iVar2 = FUN_10057d00();
  uVar6 = 0;
  local_3c = auStack_120 + 0x80;
  do {
    while( true ) {
      uVar5 = uVar6;
      uVar6 = uVar5 + 1;
      if (*(uint *)(param_1 + 0x6c) < uVar6) {
        FUN_1006dde0(local_5c);
        return;
      }
      piVar1 = *(int **)(*(int *)(param_1 + 0x68) + uVar6 * 4 + -4);
      iVar4 = *piVar1;
      cVar3 = FUN_10055af0(param_1 + 0x34,piVar1[6]);
      if (cVar3 != '\0') break;
LAB_1000d980:
      FUN_100069b0(param_1,iVar4,s_Upload_aborted_100904c4);
      FUN_10055630(param_1 + 0x68,piVar1);
      FUN_1006d3e0(iVar4);
      FUN_1002b2f0(piVar1[1]);
      FUN_1006d290(piVar1);
      if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
        *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
      }
      uVar6 = uVar5;
      if (*(int *)(param_1 + 0x8c) != 0) {
        FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                     *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                     *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                     *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                     *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
      }
    }
    if (iVar4 == 0) {
      if (500 < (uint)(iVar2 - piVar1[3])) {
        FUN_10055630(param_1 + 0x68,piVar1);
        FUN_1002b2f0(piVar1[1]);
        FUN_1006d290(piVar1);
        FUN_10006860(param_1,s_Upload_aborted__no_response__100904a7);
        if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
          *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
        }
        uVar6 = uVar5;
        if (*(int *)(param_1 + 0x8c) != 0) {
          FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                       *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                       *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                       *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                       *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
        }
      }
    }
    else {
      cVar3 = FUN_1006da10(iVar4);
      if ((cVar3 == '\0') || (0x78 < (uint)(iVar2 - piVar1[3]))) goto LAB_1000d980;
      local_24 = auStack_120 + 0x80;
      while (cVar3 = FUN_1006df20(iVar4,&local_5c,local_58), cVar3 != '\0') {
        FUN_1002ddf0(piVar1[1],local_5c,local_58[0]);
        piVar1[4] = piVar1[4] + local_58[0];
        piVar1[3] = iVar2;
        FUN_1006dde0(local_5c);
        local_5c = 0;
      }
      if ((uint)piVar1[5] <= (uint)piVar1[4]) {
        FUN_100069b0(param_1,iVar4,s_Upload_complete_100904d3);
        FUN_10055630(param_1 + 0x68,piVar1);
        FUN_1002ddf0(piVar1[1],0,0);
        FUN_1006daf0(iVar4);
        FUN_1002b2f0(piVar1[1]);
        FUN_1006d3e0(iVar4);
        FUN_1006d290(piVar1);
        if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
          *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
        }
        uVar6 = uVar5;
        if (*(int *)(param_1 + 0x8c) != 0) {
          FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                       *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                       *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                       *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                       *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
        }
      }
    }
  } while( true );
}

