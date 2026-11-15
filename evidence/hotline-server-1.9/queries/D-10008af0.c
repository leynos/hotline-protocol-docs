
void FUN_10008af0(int param_1)

{
  bool bVar1;
  char cVar5;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort uVar6;
  undefined2 *puVar7;
  undefined1 *puVar8;
  undefined1 auStack_2130 [128];
  undefined4 local_2068;
  undefined4 local_2064;
  undefined4 local_2060;
  undefined4 local_205c;
  undefined4 local_2058;
  undefined4 local_2054;
  undefined4 local_2050;
  undefined4 local_204c;
  undefined4 local_2048;
  undefined4 local_2044;
  undefined4 local_2040;
  undefined4 local_203c;
  undefined1 *local_2024;
  undefined2 local_2020;
  ushort local_201e;
  undefined2 local_201c;
  undefined2 local_201a;
  undefined2 local_2018;
  undefined2 local_2016;
  undefined2 local_2014;
  undefined2 local_2012;
  undefined2 local_2010;
  undefined2 local_200e;
  undefined2 local_200c;
  undefined2 local_200a;
  undefined2 local_2008;
  undefined2 local_2006;
  undefined2 local_2004;
  undefined1 local_2002 [14];
  byte local_1ff4 [6];
  undefined1 local_1fee [8154];
  
  uVar6 = 0;
  local_2060 = 0;
  local_205c = 0;
  local_2068 = 0;
  local_2064 = 0;
  local_2050 = 0;
  local_204c = 0;
  local_2058 = 0;
  local_2054 = 0;
  local_2040 = 0;
  local_203c = 0;
  local_2048 = 0;
  local_2044 = 0;
  if (*(int *)(param_1 + 0x94) != 0) {
    cVar5 = FUN_1003a6b0(*(undefined4 *)(*(int *)(param_1 + 0x94) + 0xc));
    uVar6 = (ushort)(cVar5 != '\0');
    FUN_1003a990(*(undefined4 *)(*(int *)(param_1 + 0x94) + 0xc),&local_2068);
  }
  if (*(int *)(param_1 + 0x8c) != 0) {
    cVar5 = FUN_1003a6b0(*(undefined4 *)(*(int *)(param_1 + 0x8c) + 0xc));
    if (cVar5 != '\0') {
      uVar6 = uVar6 | 4;
    }
    FUN_1003a990(*(undefined4 *)(*(int *)(param_1 + 0x8c) + 0xc),&local_2058);
  }
  if (*(int *)(param_1 + 0x90) != 0) {
    cVar5 = FUN_1003a6b0(*(undefined4 *)(*(int *)(param_1 + 0x90) + 0xc));
    if (cVar5 != '\0') {
      uVar6 = uVar6 | 2;
    }
    FUN_1003a990(*(undefined4 *)(*(int *)(param_1 + 0x90) + 0xc),&local_2048);
  }
  cVar5 = FUN_1006eaa0();
  if (cVar5 == '\0') {
    *(uint *)(param_1 + 0xac) = *(uint *)(param_1 + 0xac) & 0xffffffef;
  }
  else {
    *(uint *)(param_1 + 0xac) = *(uint *)(param_1 + 0xac) | 0x10;
  }
  local_2020 = 5;
  local_201c = (undefined2)local_2068;
  local_201a = (undefined2)local_2064;
  local_2018 = (undefined2)local_2060;
  local_2016 = (undefined2)local_205c;
  local_2014 = (undefined2)local_2048;
  local_2012 = (undefined2)local_2044;
  local_2010 = (undefined2)local_2040;
  local_200e = (undefined2)local_203c;
  local_200c = (undefined2)local_2058;
  local_200a = (undefined2)local_2054;
  local_2008 = (undefined2)local_2050;
  local_2006 = (undefined2)local_204c;
  iVar2 = 0x1a;
  puVar7 = &local_2004;
  while (bVar1 = iVar2 != 0, iVar2 = iVar2 + -1, bVar1) {
    *(undefined1 *)puVar7 = 0;
    puVar7 = (undefined2 *)((int)puVar7 + 1);
  }
  *puVar7 = *(undefined2 *)(param_1 + 0xa8);
  *(undefined1 *)(puVar7 + 1) = *(undefined1 *)(param_1 + 0x9c);
  *(undefined1 *)((int)puVar7 + 3) = *(undefined1 *)(param_1 + 0x9d);
  *(undefined1 *)(puVar7 + 2) = *(undefined1 *)(param_1 + 0x9e);
  *(undefined1 *)((int)puVar7 + 5) = *(undefined1 *)(param_1 + 0x9f);
  *(undefined4 *)(puVar7 + 3) = *(undefined4 *)(param_1 + 0xac);
  puVar7[5] = *(undefined2 *)(param_1 + 0xa0);
  puVar7[6] = *(undefined2 *)(param_1 + 0xa4);
  puVar7[7] = *(undefined2 *)(param_1 + 0xa6);
  *(byte *)(puVar7 + 8) = (byte)(-(uint)DAT_10093be9 >> 0x1f);
  *(undefined1 *)((int)puVar7 + 0x11) = 0;
  *(undefined4 *)(puVar7 + 9) = *(undefined4 *)(param_1 + 0x454);
  *(undefined1 *)(puVar7 + 0xb) = 0;
  *(undefined1 *)((int)puVar7 + 0x17) = 0;
  *(undefined1 *)(puVar7 + 0xc) = 0;
  local_201e = uVar6;
  iVar2 = FUN_100539c0((undefined1 *)((int)puVar7 + 0x19),param_1 + 0xcc,
                       *(byte *)(param_1 + 0xcc) + 1);
  puVar8 = (undefined1 *)((int)puVar7 + 0x19) + iVar2;
  *puVar8 = 0;
  puVar8 = puVar8 + 1;
  iVar2 = FUN_100539c0(puVar8,param_1 + 0xec,*(byte *)(param_1 + 0xec) + 1);
  puVar8 = puVar8 + iVar2;
  iVar2 = FUN_100539c0(puVar8,param_1 + 0x16c,*(byte *)(param_1 + 0x16c) + 1);
  puVar8 = puVar8 + iVar2;
  iVar2 = FUN_100539c0(puVar8,param_1 + 0x18c,*(byte *)(param_1 + 0x18c) + 1);
  puVar8 = puVar8 + iVar2;
  iVar2 = FUN_100539c0(puVar8,param_1 + 0x20c,*(byte *)(param_1 + 0x20c) + 1);
  iVar3 = FUN_100539c0(puVar8 + iVar2,param_1 + 0x30c,*(byte *)(param_1 + 0x30c) + 1);
  puVar8 = puVar8 + iVar2 + iVar3;
  for (iVar2 = 0; iVar2 != 5; iVar2 = iVar2 + 1) {
    iVar3 = FUN_100539c0(puVar8,param_1 + iVar2 * 0x144 + 0x45c,
                         *(byte *)(param_1 + iVar2 * 0x144 + 0x45c) + 1);
    puVar8 = puVar8 + iVar3;
    iVar3 = FUN_100539c0(puVar8,param_1 + iVar2 * 0x144 + 0x55c,
                         *(byte *)(param_1 + iVar2 * 0x144 + 0x55c) + 1);
    iVar4 = FUN_100539c0(puVar8 + iVar3,param_1 + iVar2 * 0x144 + 0x57c,
                         *(byte *)(param_1 + iVar2 * 0x144 + 0x57c) + 1);
    puVar8 = puVar8 + iVar3 + iVar4;
  }
  iVar2 = FUN_1002af80(0xfffffffe,0,0x100902d9,0,0);
  FUN_1002b410(iVar2,0x70726566,0x48544c53,4,0x23);
  local_2024 = auStack_2130 + 0x80;
  FUN_1002c5a0(iVar2,(int)puVar8 - (int)&local_2020);
  FUN_1002c440(iVar2,0,&local_2020,(int)puVar8 - (int)&local_2020,0);
  if (iVar2 != 0) {
    FUN_1002b2f0(iVar2);
  }
  return;
}

