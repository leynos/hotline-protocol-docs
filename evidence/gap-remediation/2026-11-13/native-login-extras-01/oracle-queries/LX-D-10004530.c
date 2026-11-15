
void FUN_10004530(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  undefined1 *puVar4;
  undefined1 local_110;
  undefined1 auStack_10f [263];
  
  if ((((*(int *)(param_1 + 0x94) != 0) && (*(int *)(param_1 + 0x18) != 0)) &&
      (*(short *)(param_1 + 0xa0) != 0)) && (*(short *)(param_1 + 0xa2) != 0)) {
    uVar1 = FUN_10058270(*(undefined4 *)(param_1 + 0x18));
    iVar2 = FUN_1006d5e0(uVar1,auStack_10f,0xff);
    puVar4 = auStack_10f + iVar2;
    if (*(short *)(param_1 + 0xa0) != 0x157c) {
      if ((int)puVar4 - (int)&local_110 != 0x100) {
        *puVar4 = 0x3a;
        puVar4 = auStack_10f + iVar2 + 1;
      }
      iVar2 = FUN_10053c10(puVar4,0xff - (int)(puVar4 + (-1 - (int)&local_110)),
                           *(undefined2 *)(param_1 + 0xa0),0);
      puVar4 = puVar4 + iVar2;
    }
    if ((int)puVar4 - (int)&local_110 != 0x100) {
      *puVar4 = 0xd;
      puVar4 = puVar4 + 1;
    }
    uVar3 = (uint)*(byte *)(param_1 + 0xcc);
    if (0xffU - (int)(puVar4 + (-1 - (int)&local_110)) <= uVar3) {
      uVar3 = 0xff - (int)(puVar4 + (-1 - (int)&local_110));
    }
    iVar2 = FUN_100539c0(puVar4,param_1 + 0xcd,uVar3);
    local_110 = SUB41(puVar4 + (iVar2 - (int)&local_110) + -1,0);
    FUN_10082630(*(undefined4 *)(*(int *)(param_1 + 0x94) + 0x14),auStack_10f,
                 (uint)(puVar4 + (iVar2 - (int)&local_110) + -1) & 0xff);
  }
  return;
}

