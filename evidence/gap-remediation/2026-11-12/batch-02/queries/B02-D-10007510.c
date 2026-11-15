
void FUN_10007510(int param_1,char *param_2,int param_3)

{
  undefined2 uVar1;
  undefined4 uVar2;
  undefined1 local_38;
  undefined1 auStack_37 [47];
  
  if (((*(int *)(param_1 + 0xb0) != 0) && (param_2 != (char *)0x0)) && (*param_2 != '\0')) {
    if (*(ushort *)(param_3 + 0x298) < 0x20) {
      uVar1 = *(undefined2 *)(param_3 + 0x298);
    }
    else {
      uVar1 = 0x1f;
    }
    local_38 = FUN_100539c0(auStack_37,param_3 + 0x29a,uVar1);
    uVar2 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),0,param_2,800,0);
    FUN_1002bc30(uVar2,&local_38,0);
    FUN_1002b2f0(uVar2);
  }
  return;
}

