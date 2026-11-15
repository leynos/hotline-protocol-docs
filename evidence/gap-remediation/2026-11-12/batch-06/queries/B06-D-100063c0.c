
void FUN_100063c0(int param_1,undefined4 param_2)

{
  undefined1 *puVar1;
  undefined1 uVar3;
  int iVar2;
  
  if ((int)((*(uint *)(param_1 + 0x440) | 0xffffffdf) - (*(uint *)(param_1 + 0x440) - 0x20 >> 1)) <
      0) {
    puVar1 = (undefined1 *)FUN_10055770(param_1 + 0x43c,1);
  }
  else {
    puVar1 = (undefined1 *)FUN_1006d260(0x74);
    if (puVar1 != (undefined1 *)0x0) {
      FUN_10009930(puVar1);
    }
  }
  if (puVar1 != (undefined1 *)0x0) {
    *puVar1 = 1;
    *(undefined4 *)(puVar1 + 8) = param_2;
    *(undefined4 *)(puVar1 + 0xc) = param_2;
    uVar3 = FUN_10057e30(puVar1 + 0x11,0x20,0x21);
    puVar1[0x10] = uVar3;
    iVar2 = FUN_10057d00();
    *(int *)(puVar1 + 4) = iVar2 + 0x708;
    puVar1[0x31] = 0;
    FUN_100554e0(param_1 + 0x43c,puVar1);
  }
  return;
}

