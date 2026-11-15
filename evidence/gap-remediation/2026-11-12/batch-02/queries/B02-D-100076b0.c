
undefined4 FUN_100076b0(int param_1,int param_2)

{
  undefined4 uVar1;
  char cVar2;
  undefined2 uVar3;
  undefined1 local_38;
  undefined1 auStack_37 [51];
  
  if (*(int *)(param_1 + 0xb0) == 0) {
    uVar1 = 0;
  }
  else {
    if (*(ushort *)(param_2 + 0x298) < 0x20) {
      uVar3 = *(undefined2 *)(param_2 + 0x298);
    }
    else {
      uVar3 = 0x1f;
    }
    local_38 = FUN_100539c0(auStack_37,param_2 + 0x29a,uVar3);
    uVar1 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),0,&local_38,0,0);
    cVar2 = FUN_1002b750(uVar1,0);
    if (cVar2 == '\0') {
      FUN_1002b2f0(uVar1);
      uVar1 = 0;
    }
    else {
      FUN_1002b2f0(uVar1);
      uVar1 = 1;
    }
  }
  return uVar1;
}

