
void FUN_10003f30(int param_1)

{
  undefined1 *puVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined1 auStack_110 [128];
  short local_50 [2];
  int local_4c;
  undefined4 local_48;
  undefined1 *local_2c;
  undefined1 *local_14;
  
  puVar1 = auStack_110 + 0x80;
  iVar2 = FUN_1002af80(0xfffffffe,0,PTR_DAT_1008ee20,0x280,local_50);
  local_14 = puVar1;
  if (local_50[0] == 1) {
    FUN_1002b370(iVar2,0x54455854,0x74747874);
  }
  local_4c = iVar2;
  local_2c = puVar1;
  FUN_1002c220(iVar2,0x21);
  uVar3 = FUN_1002c4d0(iVar2,0);
  if (*(int *)(param_1 + 4) == 0) {
    uVar4 = FUN_10052c50(uVar3,0);
    *(undefined4 *)(param_1 + 4) = uVar4;
  }
  else {
    FUN_10053130(*(undefined4 *)(param_1 + 4),uVar3);
  }
  local_48 = *(undefined4 *)(param_1 + 4);
  uVar4 = FUN_10053290();
  FUN_1002c3b0(iVar2,0,uVar4,uVar3,0);
  FUN_10053310(local_48);
  FUN_10006860(param_1,s_Loaded_MessageBoard_txt_1008fce1);
  if (local_4c != 0) {
    FUN_1002b2f0(local_4c);
  }
  return;
}

