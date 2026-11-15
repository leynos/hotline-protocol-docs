
void FUN_1000bd20(int param_1)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  char cVar5;
  undefined4 *puVar4;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined1 auStack_140 [128];
  int local_80;
  undefined4 local_7c;
  int local_78;
  int local_74;
  undefined1 auStack_70 [4];
  uint local_6c;
  int local_60;
  uint local_5c;
  undefined4 local_58;
  short local_54;
  undefined1 *local_3c;
  
LAB_1000bd40:
  do {
    local_80 = 0;
    local_7c = 0xc;
    if (*(int *)(param_1 + 0x20) != 0) {
      local_80 = FUN_1006dcd0(*(undefined4 *)(param_1 + 0x20),auStack_70,&local_7c);
    }
    if (local_80 == 0) {
      if (*(int *)(param_1 + 0x24) != 0) {
        local_80 = FUN_1006dcd0(*(undefined4 *)(param_1 + 0x24),auStack_70,&local_7c);
      }
      uVar9 = 0;
      if (local_80 == 0) break;
    }
    uVar9 = local_6c;
    if (-1 < *(char *)(param_1 + 200)) {
      uVar6 = 0;
      do {
        uVar6 = uVar6 + 1;
        if (*(uint *)(param_1 + 0x44c) < uVar6) {
          bVar1 = false;
          goto LAB_1000be3c;
        }
        local_78 = *(int *)(*(int *)(param_1 + 0x448) + uVar6 * 4 + -4);
        bVar1 = false;
        if ((*(uint *)(local_78 + 8) <= local_6c) && (local_6c <= *(uint *)(local_78 + 0xc))) {
          bVar1 = true;
        }
      } while (!bVar1);
      bVar1 = true;
LAB_1000be3c:
      if (!bVar1) {
        uVar6 = *(uint *)(param_1 + 0x440);
        if (uVar6 != 0) {
          uVar3 = FUN_10057d00();
          for (uVar8 = 1; uVar8 <= uVar6; uVar8 = uVar8 + 1) {
            bVar1 = false;
            if ((uVar8 != 0) && (uVar8 <= *(uint *)(param_1 + 0x440))) {
              bVar1 = true;
            }
            if (bVar1) {
              iVar7 = *(int *)(*(int *)(param_1 + 0x43c) + uVar8 * 4 + -4);
            }
            else {
              iVar7 = 0;
            }
            if (*(uint *)(iVar7 + 4) <= uVar3) {
              FUN_10055770(param_1 + 0x43c,uVar8);
              FUN_1006d290(iVar7);
            }
          }
        }
        uVar6 = 0;
        do {
          uVar6 = uVar6 + 1;
          if (*(uint *)(param_1 + 0x440) < uVar6) {
            bVar1 = false;
            goto LAB_1000bf54;
          }
          local_74 = *(int *)(*(int *)(param_1 + 0x43c) + uVar6 * 4 + -4);
          bVar1 = false;
          if ((*(uint *)(local_74 + 8) <= uVar9) && (uVar9 <= *(uint *)(local_74 + 0xc))) {
            bVar1 = true;
          }
        } while (!bVar1);
        bVar1 = true;
LAB_1000bf54:
        if (!bVar1) {
          local_3c = auStack_140 + 0x80;
          FUN_1006d440(local_80,PTR_PTR_10088d98,param_1);
          FUN_100554e0(param_1 + 0x80,local_80);
          goto LAB_1000bd40;
        }
      }
    }
    FUN_1006d3e0(local_80);
  } while( true );
LAB_1000c1a4:
  do {
    uVar6 = uVar9;
    uVar9 = uVar6 + 1;
    if (*(uint *)(param_1 + 0x84) < uVar9) {
      return;
    }
    uVar2 = *(undefined4 *)(*(int *)(param_1 + 0x80) + uVar9 * 4 + -4);
    cVar5 = FUN_1006e120(uVar2,0x10);
  } while (cVar5 == '\0');
  FUN_1006dfb0(uVar2,&local_60,0x10);
  if (local_60 != 0x48545846) goto LAB_1000c174;
  if ((local_5c & 1) == 0) {
    if (local_54 == 1) {
      puVar4 = (undefined4 *)FUN_1000ec80(param_1,local_5c);
      if (puVar4 == (undefined4 *)0x0) goto LAB_1000c174;
      FUN_10055630(param_1 + 0x80,uVar2);
      *puVar4 = uVar2;
    }
    else {
      puVar4 = (undefined4 *)FUN_1000ec40(param_1,local_5c);
      if (puVar4 == (undefined4 *)0x0) goto LAB_1000c174;
      FUN_10055630(param_1 + 0x80,uVar2);
      *puVar4 = uVar2;
      puVar4[5] = local_58;
    }
    FUN_100069b0(param_1,uVar2,s_Upload_connection_established_100903d8);
    uVar9 = uVar6;
    goto LAB_1000c1a4;
  }
  if (local_54 == 2) {
    puVar4 = (undefined4 *)FUN_1000e720(param_1,local_5c);
    if (puVar4 != (undefined4 *)0x0) {
      FUN_10055630(param_1 + 0x80,uVar2);
      *puVar4 = uVar2;
      goto LAB_1000c0cc;
    }
LAB_1000c174:
    FUN_100069b0(param_1,uVar2,s_Transfer_connection_establish_fa_100903f6);
    FUN_10055630(param_1 + 0x80,uVar2);
    FUN_1006d3e0(uVar2);
    uVar9 = uVar6;
  }
  else {
    if (local_54 != 1) {
      puVar4 = (undefined4 *)FUN_1000e600(param_1,local_5c);
      if (puVar4 != (undefined4 *)0x0) {
        FUN_10055630(param_1 + 0x80,uVar2);
        *puVar4 = uVar2;
        goto LAB_1000c0cc;
      }
      goto LAB_1000c174;
    }
    puVar4 = (undefined4 *)FUN_1000e690(param_1,local_5c);
    if (puVar4 == (undefined4 *)0x0) goto LAB_1000c174;
    FUN_10055630(param_1 + 0x80,uVar2);
    *puVar4 = uVar2;
LAB_1000c0cc:
    FUN_100069b0(param_1,uVar2,s_Download_connection_established_100903b8);
    uVar9 = uVar6;
  }
  goto LAB_1000c1a4;
}

