
undefined4 FUN_10018e10(int param_1)

{
  bool bVar1;
  byte bVar2;
  uint uVar3;
  undefined1 *puVar4;
  undefined1 uVar6;
  undefined4 uVar5;
  undefined1 local_90;
  undefined1 auStack_8f [63];
  byte local_50;
  undefined1 auStack_4f [67];
  
  local_90 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x70) + 0x2c),auStack_8f,0x3f);
  local_50 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x74) + 0x2c),auStack_4f,0x3f);
  bVar1 = true;
  uVar3 = FUN_10082630(param_1);
  if (uVar3 < 500) {
    puVar4 = (undefined1 *)FUN_1006d260(0x74);
    if (puVar4 != (undefined1 *)0x0) {
      FUN_10009930(puVar4);
    }
  }
  else {
    FUN_1006aa40(param_1);
    puVar4 = (undefined1 *)FUN_1001b000(param_1,1);
    bVar1 = false;
  }
  *puVar4 = 1;
  FUN_10009990(puVar4,&local_90);
  uVar6 = FUN_10057e30(puVar4 + 0x11,0x20,0x22);
  puVar4[0x10] = uVar6;
  *(undefined4 *)(puVar4 + 4) = 0xffffffff;
  if (local_50 < 0x40) {
    bVar2 = local_50;
  }
  else {
    bVar2 = 0x3f;
  }
  puVar4[0x31] = bVar2;
  FUN_100539c0(puVar4 + 0x32,auStack_4f,bVar2);
  *(undefined4 *)(param_1 + 0x78) = 0;
  if (bVar1) {
    uVar5 = FUN_1001b060(param_1,puVar4,1);
  }
  else {
    uVar5 = 0;
  }
  FUN_10082630(param_1,uVar5,1);
  if (!bVar1) {
    FUN_10069f70(param_1,uVar5);
  }
  return uVar5;
}

