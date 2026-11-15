
void FUN_10009d10(int param_1,int *param_2)

{
  bool bVar1;
  char *pcVar2;
  int iVar3;
  char cVar7;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar8;
  undefined1 auStack_110 [128];
  undefined2 local_50 [2];
  uint local_4c;
  int local_48;
  int local_44;
  int local_40;
  undefined1 *local_24;
  
  iVar3 = FUN_1002af80(0xfffffffe,0,s_Banned_Banned_bakToo_many_resets_100902ee + 6,0,0);
  local_44 = iVar3;
  cVar7 = FUN_1002b750(iVar3,0);
  if (cVar7 != '\0') {
    FUN_1002b880(iVar3);
  }
  iVar3 = FUN_1002af80(0xfffffffe,0,0x100902ed,0,0);
  local_40 = iVar3;
  cVar7 = FUN_1002b750(iVar3,0);
  if (cVar7 != '\0') {
    FUN_1002bc30(iVar3,s_Banned_Banned_bakToo_many_resets_100902ee + 6,0);
  }
  if (local_40 != 0) {
    FUN_1002b2f0(local_40);
  }
  if (local_44 != 0) {
    FUN_1002b2f0(local_44);
  }
  FUN_1000a550(param_1);
  local_4c = param_2[1];
  if (local_4c != 0) {
    iVar3 = FUN_1002af80(0xfffffffe,0,0x100902ed,0,0);
    local_48 = iVar3;
    FUN_1002b410(iVar3,0x62616e6e,0x48544c53,4,0x23);
    local_50[0] = 2;
    local_24 = auStack_110 + 0x80;
    iVar4 = FUN_1002c440(iVar3,0,local_50,2,0);
    iVar5 = FUN_1002c440(iVar3,iVar4,&local_4c,4,0);
    iVar4 = iVar4 + iVar5;
    local_4c = param_2[1];
    for (uVar8 = 1; uVar8 <= local_4c; uVar8 = uVar8 + 1) {
      bVar1 = false;
      if (uVar8 != 0) {
        if (uVar8 <= (uint)param_2[1]) {
          bVar1 = true;
        }
      }
      if (bVar1) {
        pcVar2 = *(char **)(*param_2 + uVar8 * 4 + -4);
      }
      else {
        pcVar2 = (char *)0x0;
      }
      iVar5 = FUN_1002c440(iVar3,iVar4,pcVar2,1,0);
      iVar6 = FUN_1002c440(iVar3,iVar4 + iVar5,pcVar2 + 8,4,0);
      iVar6 = iVar4 + iVar5 + iVar6;
      iVar4 = FUN_1002c440(iVar3,iVar6,pcVar2 + 0xc,4,0);
      iVar6 = iVar6 + iVar4;
      iVar4 = FUN_1002c440(iVar3,iVar6,pcVar2 + 0x10,0x21,0);
      iVar6 = iVar6 + iVar4;
      iVar4 = FUN_1002c440(iVar3,iVar6,pcVar2 + 0x31,(byte)pcVar2[0x31] + 1,0);
      iVar4 = iVar6 + iVar4;
      if (*pcVar2 == '\0') {
        FUN_1006d290(pcVar2);
      }
      else {
        FUN_100554e0(param_1 + 0x448,pcVar2);
      }
    }
    FUN_10055880(param_2);
    FUN_1002c2c0(iVar3);
    if (local_48 != 0) {
      FUN_1002b2f0(local_48);
    }
  }
  return;
}

