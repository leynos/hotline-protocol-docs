
void FUN_10011870(int param_1,undefined4 param_2,undefined4 param_3)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined2 local_128;
  undefined2 local_126;
  undefined2 local_124;
  ushort local_122;
  undefined1 auStack_120 [268];
  
  uVar2 = FUN_10056380(0,0);
  puVar4 = *(undefined4 **)(param_1 + 0x34);
  while( true ) {
    if (puVar4 == (undefined4 *)0x0) break;
    if (*(char *)((int)puVar4 + 0x14a) < '\0') {
      local_128 = *(undefined2 *)(puVar4 + 5);
      local_126 = *(undefined2 *)((int)puVar4 + 0x16);
      local_124 = FUN_10005000(param_1,puVar4);
      bVar1 = *(byte *)(puVar4 + 0xe);
      uVar3 = (uint)bVar1;
      FUN_100539c0(auStack_120,(int)puVar4 + 0x39,uVar3);
      local_122 = (ushort)bVar1;
      if (uVar3 == 0) {
        puVar4 = (undefined4 *)*puVar4;
      }
      else {
        FUN_100568b0(uVar2,300,&local_128,uVar3 + 8);
        puVar4 = (undefined4 *)*puVar4;
      }
    }
    else {
      puVar4 = (undefined4 *)*puVar4;
    }
  }
  FUN_10058a70(param_3,uVar2);
  FUN_100563d0(uVar2);
  return;
}

