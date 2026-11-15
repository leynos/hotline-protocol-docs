
void FUN_10003940(int param_1,undefined4 param_2)

{
  char cVar2;
  short sVar1;
  int local_20 [5];
  
  FUN_10003bd0(param_1,PTR_DAT_1008ee24,param_2,param_1 + 8,local_20);
  *(undefined4 *)(param_1 + 0x10) = 0;
  if ((*(uint *)(param_1 + 0xac) >> 7 & 1) == 0) {
    if (*(int *)(param_1 + 0xc) != 0) {
      FUN_10052e90(*(undefined4 *)(param_1 + 0xc));
      *(undefined4 *)(param_1 + 0xc) = 0;
    }
    cVar2 = FUN_10003e80(param_1,param_1 + 0x30c,param_1 + 0x14);
    if (cVar2 == '\0') {
      return;
    }
    *(undefined4 *)(param_1 + 0x10) = 0x55524c20;
    return;
  }
  if (*(int *)(param_1 + 0x14) != 0) {
    FUN_10052e90(*(undefined4 *)(param_1 + 0x14));
    *(undefined4 *)(param_1 + 0x14) = 0;
  }
  cVar2 = FUN_10003bd0(param_1,param_1 + 0x18c,param_2,param_1 + 0xc,local_20);
  if (cVar2 == '\0') {
    return;
  }
  local_20[1] = 0;
  if (4 < *(byte *)(param_1 + 0x18c)) {
    FUN_100539c0(local_20 + 1,param_1 + *(byte *)(param_1 + 0x18c) + 0x189,4);
    FUN_100541e0(local_20 + 1,4,0);
  }
  sVar1 = FUN_1006d130(local_20 + 1,0x1008fc1f,4);
  if (((sVar1 == 0) || (local_20[0] == 0x4a504547)) || (local_20[0] == 0x4a464946)) {
    *(undefined4 *)(param_1 + 0x10) = 0x4a504547;
  }
  else {
    sVar1 = FUN_1006d130(local_20 + 1,0x1008fc24,4);
    if ((sVar1 == 0) || (local_20[0] == 0x47494666)) {
      *(undefined4 *)(param_1 + 0x10) = 0x47494666;
    }
    else {
      sVar1 = FUN_1006d130(local_20 + 1,0x1008fc29,4);
      if ((sVar1 == 0) || (local_20[0] == 0x50494354)) {
        *(undefined4 *)(param_1 + 0x10) = 0x50494354;
      }
      else {
        sVar1 = FUN_1006d130(local_20 + 1,0x1008fc2e,4);
        if (((sVar1 == 0) || (sVar1 = FUN_1006d130(local_20 + 1,0x1008fc33,4), sVar1 == 0)) ||
           (local_20[0] == 0x424d5020)) {
          *(undefined4 *)(param_1 + 0x10) = 0x424d5020;
        }
      }
    }
  }
  if (*(int *)(param_1 + 0x10) == 0) {
    *(int *)(param_1 + 0x10) = local_20[0];
  }
  FUN_10003e80(param_1,param_1 + 0x20c,param_1 + 0x14);
  return;
}

