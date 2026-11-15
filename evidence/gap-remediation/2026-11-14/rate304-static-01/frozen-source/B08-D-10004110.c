
int FUN_10004110(int param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined1 auStack_280 [128];
  short local_1c0 [2];
  undefined4 local_1bc;
  int local_1b8;
  undefined1 auStack_1b0 [2];
  undefined2 local_1ae;
  undefined2 local_1ac;
  undefined2 local_1aa;
  undefined2 local_1a8;
  undefined1 *local_18c;
  undefined4 local_188;
  undefined4 local_184;
  undefined4 local_180;
  undefined4 local_17c;
  undefined4 local_178;
  undefined4 local_174;
  undefined4 local_170;
  undefined4 local_16c;
  undefined4 local_168;
  undefined1 local_164;
  undefined4 local_160;
  undefined4 local_15c;
  undefined4 local_158;
  undefined4 local_154;
  undefined4 local_150;
  undefined4 local_14c;
  undefined4 local_148;
  undefined4 local_144;
  undefined4 local_140;
  undefined4 local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  undefined4 local_12c;
  undefined4 local_128;
  undefined1 local_124;
  undefined1 auStack_120 [260];
  
  if (*(int *)(param_1 + 4) == 0) {
    FUN_10027c30(1,2);
  }
  local_188 = *(undefined4 *)PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148;
  local_184 = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 4);
  local_180 = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 8);
  local_17c = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 0xc);
  local_178 = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 0x10);
  local_174 = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 0x14);
  local_170 = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 0x18);
  local_16c = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 0x1c);
  local_168 = *(undefined4 *)(PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148 + 0x20);
  local_164 = PTR_s_From___s___s_2_2hu__2_2hu__2_2hu_10089148[0x24];
  local_160 = *(uint *)PTR_s_<________________________________10089144;
  local_15c = *(undefined4 *)(PTR_s_<________________________________10089144 + 4);
  local_158 = *(undefined4 *)(PTR_s_<________________________________10089144 + 8);
  local_154 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0xc);
  local_150 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x10);
  local_14c = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x14);
  local_148 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x18);
  local_144 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x1c);
  local_140 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x20);
  local_13c = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x24);
  local_138 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x28);
  local_134 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x2c);
  local_130 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x30);
  local_12c = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x34);
  local_128 = *(undefined4 *)(PTR_s_<________________________________10089144 + 0x38);
  local_124 = PTR_s_<________________________________10089144[0x3c];
  iVar2 = FUN_100567c0(param_2,0x65);
  FUN_10057d70(1,auStack_1b0);
  switch(local_1ae) {
  default:
    uVar6 = 0x1008fd29;
    break;
  case 1:
    uVar6 = 0x1008fcf9;
    break;
  case 2:
    uVar6 = 0x1008fcfd;
    break;
  case 3:
    uVar6 = 0x1008fd01;
    break;
  case 4:
    uVar6 = 0x1008fd05;
    break;
  case 5:
    uVar6 = 0x1008fd09;
    break;
  case 6:
    uVar6 = 0x1008fd0d;
    break;
  case 7:
    uVar6 = 0x1008fd11;
    break;
  case 8:
    uVar6 = 0x1008fd15;
    break;
  case 9:
    uVar6 = 0x1008fd19;
    break;
  case 10:
    uVar6 = 0x1008fd1d;
    break;
  case 0xb:
    uVar6 = 0x1008fd21;
    break;
  case 0xc:
    uVar6 = 0x1008fd25;
  }
  iVar3 = FUN_10054180(auStack_120,0x100,&local_188,param_3,uVar6,local_1ac,local_1aa,local_1a8);
  FUN_100534d0(*(undefined4 *)(param_1 + 4),0,0,(local_160 >> 0x18) + iVar3 + iVar2);
  local_1bc = *(undefined4 *)(param_1 + 4);
  iVar4 = FUN_10053290();
  FUN_100539c0(iVar4,auStack_120,iVar3);
  FUN_10056b60(param_2,0x65,iVar4 + iVar3,iVar2);
  FUN_100539c0(iVar2 + iVar4 + iVar3,(int)&local_160 + 1,local_160._0_1_);
  iVar5 = FUN_1002af80(0xfffffffe,0,PTR_DAT_1008ee20,0x280,local_1c0);
  local_18c = auStack_280 + 0x80;
  if (local_1c0[0] == 1) {
    FUN_1002b370(iVar5,0x54455854,0x74747874);
  }
  local_1b8 = iVar5;
  FUN_1002c220(iVar5,0x23);
  uVar6 = FUN_10052f80(*(undefined4 *)(param_1 + 4));
  FUN_1002c5a0(iVar5,uVar6);
  FUN_1002c440(iVar5,0,iVar4,uVar6,0);
  uVar1 = local_160 >> 0x18;
  if (local_1b8 != 0) {
    FUN_1002b2f0(local_1b8);
  }
  FUN_10053310(local_1bc);
  return uVar1 + iVar3 + iVar2;
}

