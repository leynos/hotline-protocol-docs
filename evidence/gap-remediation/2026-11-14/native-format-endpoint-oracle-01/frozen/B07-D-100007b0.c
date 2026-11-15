
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_100007b0(uint param_1)

{
  undefined1 *puVar1;
  bool bVar2;
  undefined *puVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 *puVar9;
  char cVar10;
  byte bVar11;
  undefined1 auStack_200 [128];
  undefined **local_16c;
  short local_140 [2];
  uint local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  undefined4 local_12c;
  undefined4 local_128;
  undefined1 auStack_124 [4];
  undefined1 auStack_120 [4];
  int local_11c;
  undefined1 auStack_118 [4];
  undefined1 auStack_114 [4];
  undefined1 auStack_110 [4];
  undefined1 auStack_10c [4];
  undefined1 auStack_108 [4];
  undefined1 auStack_104 [4];
  undefined2 local_100;
  short sStack_fe;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined1 *local_dc;
  undefined1 *local_c4;
  undefined1 *local_ac;
  int local_a8;
  int local_a4;
  int local_a0;
  int local_9c;
  int local_98;
  int local_94;
  int local_90;
  int local_8c;
  int local_88;
  int local_84;
  int local_80;
  int local_7c;
  byte local_78 [72];
  
  puVar3 = PTR_PTR_10088d98;
  puVar1 = auStack_200 + 0x80;
  puVar4 = (undefined4 *)FUN_100014c0();
  iVar5 = FUN_100014b0(puVar4[8]);
  local_ac = puVar1;
  iVar6 = FUN_100014b0(*puVar4);
  _DAT_10096074 = _DAT_10096074 - iVar6;
  iVar6 = FUN_100014b0(puVar4[7]);
  _DAT_10096074 = _DAT_10096074 + iVar6;
  iVar6 = FUN_10028fc0();
  if (iVar6 != 0) {
    FUN_100014a0(auStack_124,iVar6);
    iVar7 = FUN_10001470(iVar6,1);
    uVar8 = FUN_10052c50(iVar7,1);
    FUN_10001460(auStack_120,uVar8);
    FUN_10001410(auStack_118,uVar8,&local_11c);
    FUN_100013d0(auStack_114,iVar6,1);
    FUN_100013a0(iVar6,0,local_11c,iVar7,0);
    puVar9 = (undefined4 *)FUN_10078210(local_11c,iVar5,auStack_110);
    FUN_10001390(auStack_10c,puVar9);
    iVar6 = FUN_100014b0(*puVar9);
    _DAT_10096074 = _DAT_10096074 + iVar6;
    for (bVar11 = 1; bVar11 < 4; bVar11 = bVar11 + 1) {
      iVar6 = FUN_100014b0(puVar4[bVar11]);
      _DAT_10096074 = _DAT_10096074 + iVar6;
      iVar6 = FUN_100014b0(puVar9[bVar11]);
      _DAT_10096074 = _DAT_10096074 - iVar6;
    }
    iVar5 = FUN_10078210(local_11c + iVar5 + 0x20,(iVar7 - iVar5) + -0x20,auStack_108);
    FUN_10001390(auStack_104,iVar5);
    bVar11 = 0;
    while( true ) {
      if (2 < bVar11) break;
      iVar6 = FUN_100014b0(puVar4[bVar11 + 4]);
      _DAT_10096074 = _DAT_10096074 - iVar6;
      iVar6 = FUN_100014b0(*(undefined4 *)(iVar5 + (uint)bVar11 * 4));
      _DAT_10096074 = _DAT_10096074 + iVar6;
      bVar11 = bVar11 + 1;
    }
    iVar5 = FUN_100014b0(*(undefined4 *)(iVar5 + 0xc));
    _DAT_10096074 = _DAT_10096074 - iVar5;
    FUN_10001320(auStack_104,0xffffffff);
    FUN_10001320(auStack_10c,0xffffffff);
    FUN_100012c0(auStack_114,0xffffffff);
    FUN_10001260(auStack_118,0xffffffff);
    FUN_100011f0(auStack_120,0xffffffff);
    FUN_10001180(auStack_124,0xffffffff);
  }
  if ((_DAT_10096074 & 3) == 0) {
    if (_DAT_10096074 >> 0x10 != param_1 >> 0x10) goto LAB_10000a48;
  }
  else {
LAB_10000a48:
    FUN_10027c30(1,1);
  }
  FUN_10028dc0(0x458,0,0,0,0,0,0);
  iVar5 = FUN_1006d260(0x1c);
  if (iVar5 != 0) {
    FUN_10020740(iVar5);
  }
  *(int *)(param_1 + 0x90) = iVar5;
  FUN_1003a450(*(undefined4 *)(iVar5 + 0xc),0x1008f8d7);
  FUN_10006a70(param_1,0x1008f8ea,0x1008f8f9);
  uVar8 = FUN_1002af80(0xfffffffe,0,0x1008f8fd,0x300,local_140);
  *(undefined4 *)(param_1 + 0xb0) = uVar8;
  if (local_140[0] == 1) {
    FUN_1002b670(*(undefined4 *)(param_1 + 0xb0));
  }
  uVar8 = FUN_1002af80(0xfffffffe,0,0x1008f903,0x300,local_140);
  *(undefined4 *)(param_1 + 0xb4) = uVar8;
  if (local_140[0] == 1) {
    FUN_1002b670(*(undefined4 *)(param_1 + 0xb4));
  }
  uVar8 = FUN_1002af80(0xfffffffe,0,0x1008f909,0x300,local_140);
  *(undefined4 *)(param_1 + 0xb8) = uVar8;
  if (local_140[0] == 1) {
    FUN_1002b670(*(undefined4 *)(param_1 + 0xb8));
  }
  FUN_10003f30(param_1);
  DAT_10093be9 = 0;
  _DAT_10094a50 = 0x80000;
  FUN_10008fd0(param_1,&local_a8,&local_13c);
  FUN_1000a460(param_1);
  FUN_10003940(param_1,0);
  iVar5 = FUN_1006d260(0x1c);
  if (iVar5 != 0) {
    FUN_1001e8a0(iVar5);
  }
  *(int *)(param_1 + 0x94) = iVar5;
  FUN_1003afe0(*(undefined4 *)(iVar5 + 0xc));
  bVar2 = false;
  if (local_a8 < local_a0) {
    if (local_9c <= local_a4) goto LAB_10000c14;
  }
  else {
LAB_10000c14:
    bVar2 = true;
  }
  if (bVar2) {
    FUN_100376b0(*(undefined4 *)(param_1 + 0x94),7,4);
  }
  else {
    FUN_10037710(*(undefined4 *)(param_1 + 0x94),&local_a8);
    if (local_9c - local_a4 < 0x33) {
      FUN_1001ecb0(*(undefined4 *)(param_1 + 0x94));
    }
    FUN_100376b0(*(undefined4 *)(param_1 + 0x94),1,4);
  }
  FUN_1003a510(*(undefined4 *)(*(int *)(param_1 + 0x94) + 0xc),1);
  bVar2 = false;
  if (local_98 < local_90) {
    if (local_8c <= local_94) goto LAB_10000cb4;
  }
  else {
LAB_10000cb4:
    bVar2 = true;
  }
  if (bVar2) {
    FUN_100376b0(*(undefined4 *)(param_1 + 0x90),6,4);
    local_16c = &_toc;
  }
  else {
    FUN_10082630(*(undefined4 *)(param_1 + 0x90),&local_98);
    FUN_100376b0(*(undefined4 *)(param_1 + 0x90),1,4);
  }
  if ((local_13c & 2) != 0) {
    FUN_1003a510(*(undefined4 *)(*(int *)(param_1 + 0x90) + 0xc),1);
  }
  iVar5 = FUN_1006d260(0x54);
  if (iVar5 != 0) {
    FUN_10020fd0(iVar5);
  }
  *(int *)(param_1 + 0x8c) = iVar5;
  bVar2 = false;
  if (local_88 < local_80) {
    if (local_84 < local_7c) goto LAB_10000d70;
  }
  bVar2 = true;
LAB_10000d70:
  if (bVar2) {
    FUN_100376b0(*(undefined4 *)(param_1 + 0x8c),9,4);
  }
  else {
    FUN_10037710(*(undefined4 *)(param_1 + 0x8c),&local_88);
    FUN_100376b0(*(undefined4 *)(param_1 + 0x8c),1,4);
  }
  if ((local_13c & 4) != 0) {
    FUN_1003a510(*(undefined4 *)(*(int *)(param_1 + 0x8c) + 0xc),1);
  }
  cVar10 = FUN_100576b0();
  if (cVar10 != '\0') {
    FUN_100023a0(param_1);
  }
  FUN_10007fa0(param_1);
  puVar4 = (undefined4 *)local_16c[-0x1d72];
  local_fc = puVar4[1];
  local_f8 = puVar4[2];
  sStack_fe = *(undefined2 *)(param_1 + 0xa0);
  local_100 = (undefined2)((uint)*puVar4 >> 0x10);
  local_dc = puVar1;
  uVar8 = FUN_10058090(1,1,0);
  *(undefined4 *)(param_1 + 0x18) = uVar8;
  local_138 = *(undefined4 *)(param_1 + 0x9c);
  FUN_10058310(*(undefined4 *)(param_1 + 0x18));
  FUN_100584a0(*(undefined4 *)(param_1 + 0x18),&local_100,0xc);
  FUN_100582b0(*(undefined4 *)(param_1 + 0x18),puVar3,param_1);
  sStack_fe = *(short *)(param_1 + 0xa0) + 1;
  uVar8 = FUN_1006d340(1,1,0);
  *(undefined4 *)(param_1 + 0x20) = uVar8;
  local_134 = *(undefined4 *)(param_1 + 0x9c);
  FUN_1006d4e0(*(undefined4 *)(param_1 + 0x20));
  FUN_1006dc40(*(undefined4 *)(param_1 + 0x20),&local_100,0xc);
  FUN_1006d440(*(undefined4 *)(param_1 + 0x20),puVar3,param_1);
  sStack_fe = *(short *)(param_1 + 0xa0) + 2;
  uVar8 = FUN_10058090(1,0,0);
  *(undefined4 *)(param_1 + 0x1c) = uVar8;
  local_130 = *(undefined4 *)(param_1 + 0x9c);
  FUN_10058310(*(undefined4 *)(param_1 + 0x1c));
  FUN_100584a0(*(undefined4 *)(param_1 + 0x1c),&local_100,0xc);
  FUN_100582b0(*(undefined4 *)(param_1 + 0x1c),puVar3,param_1);
  _local_100 = CONCAT22(local_100,*(short *)(param_1 + 0xa0) + 3);
  uVar8 = FUN_1006d340(1,0,0);
  *(undefined4 *)(param_1 + 0x24) = uVar8;
  local_12c = *(undefined4 *)(param_1 + 0x9c);
  FUN_1006d4e0(*(undefined4 *)(param_1 + 0x24));
  FUN_1006dc40(*(undefined4 *)(param_1 + 0x24),&local_100,0xc);
  FUN_1006d440(*(undefined4 *)(param_1 + 0x24),puVar3,param_1);
  *(undefined2 *)(param_1 + 0xa2) = *(undefined2 *)(param_1 + 0xa0);
  local_c4 = puVar1;
  uVar8 = FUN_10058270(*(undefined4 *)(param_1 + 0x18));
  local_78[0] = FUN_1006d5e0(uVar8,local_78 + 1,0x3f);
  if (*(short *)(param_1 + 0xa0) != 0x157c) {
    local_78[0] = local_78[0] + 1;
    local_78[local_78[0]] = 0x3a;
    cVar10 = FUN_10053c10(local_78 + local_78[0] + 1,10,*(undefined2 *)(param_1 + 0xa0),0);
    local_78[0] = local_78[0] + cVar10;
  }
  FUN_10006a70(param_1,local_78,0x1008fa3a);
  uVar8 = FUN_1006d340(2,1,0);
  *(undefined4 *)(param_1 + 0x28) = uVar8;
  local_128 = *(undefined4 *)(param_1 + 0x9c);
  FUN_1006d4e0(*(undefined4 *)(param_1 + 0x28));
  uVar8 = FUN_1002a260(puVar3,param_1);
  *(undefined4 *)(param_1 + 0x2c) = uVar8;
  if ((*(uint *)(param_1 + 0xac) & 1) != 0) {
    FUN_1002a410(*(undefined4 *)(param_1 + 0x2c),300000,1);
    FUN_1002a570(*(undefined4 *)(param_1 + 0x2c));
  }
  FUN_10028dc0(0x456,0,0,0,0,0,0);
  if ((*(byte *)(param_1 + 200) >> 6 & 1) != 0) {
    FUN_10028dc0(1000,0,0,0,0,0,0);
  }
  FUN_10057380(0);
  return;
}

