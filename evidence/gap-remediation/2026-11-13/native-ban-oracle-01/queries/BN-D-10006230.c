
void FUN_10006230(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined1 *param_4)

{
  undefined1 *puVar1;
  undefined1 uVar2;
  undefined1 auStack_30 [4];
  uint local_2c;
  
  FUN_10055460(auStack_30);
  FUN_1000a070(param_1,auStack_30);
  if ((int)((local_2c | 0xfffffe0b) - (local_2c - 500 >> 1)) < 0) {
    puVar1 = (undefined1 *)FUN_10055770(auStack_30,1);
  }
  else {
    puVar1 = (undefined1 *)FUN_1006d260(0x74);
    if (puVar1 != (undefined1 *)0x0) {
      FUN_10009930(puVar1);
    }
  }
  if (puVar1 == (undefined1 *)0x0) {
    FUN_10055480(auStack_30,0);
  }
  else {
    *puVar1 = 1;
    *(undefined4 *)(puVar1 + 8) = param_2;
    *(undefined4 *)(puVar1 + 0xc) = param_3;
    uVar2 = FUN_10057e30(puVar1 + 0x11,0x20,0x21);
    puVar1[0x10] = uVar2;
    *(undefined4 *)(puVar1 + 4) = 0xffffffff;
    if (param_4 == (undefined1 *)0x0) {
      puVar1[0x31] = 0;
    }
    else {
      puVar1[0x31] = *param_4;
    }
    if (0x40 < (byte)puVar1[0x31] + 1) {
      puVar1[0x31] = 0x3f;
    }
    if (param_4 != (undefined1 *)0x0) {
      FUN_100539c0(puVar1 + 0x32,param_4,puVar1[0x31]);
    }
    FUN_100554e0(auStack_30,puVar1);
    FUN_10009d10(param_1,auStack_30);
    FUN_10055480(auStack_30,0);
  }
  return;
}

