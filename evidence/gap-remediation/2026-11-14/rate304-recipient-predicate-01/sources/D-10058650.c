
undefined4 FUN_10058650(undefined4 *param_1,undefined4 *param_2,undefined2 *param_3)

{
  short sVar3;
  undefined4 uVar1;
  char cVar4;
  int iVar2;
  int local_20;
  undefined4 local_1c;
  short local_18;
  undefined2 local_16;
  
  sVar3 = FUN_1006da80(*param_1);
  if (sVar3 == 3) {
    if (*(char *)(param_1 + 0x13) < '\0') {
      *param_2 = param_1[0x11];
      *param_3 = *(undefined2 *)((int)param_1 + 0x4a);
      uVar1 = 1;
    }
    else {
      cVar4 = FUN_1006e120(*param_1,0xc);
      if ((cVar4 == '\0') || (iVar2 = FUN_1006dfb0(*param_1,&local_20,0xc), iVar2 == 0)) {
        uVar1 = 0;
      }
      else if (local_20 == 0x54525450) {
        if (local_18 == 1) {
          param_1[0x11] = local_1c;
          *param_2 = local_1c;
          *(undefined2 *)((int)param_1 + 0x4a) = local_16;
          *param_3 = local_16;
          uVar1 = 1;
        }
        else {
          FUN_100587f0(param_1,1);
          uVar1 = 3;
        }
      }
      else {
        uVar1 = 2;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

