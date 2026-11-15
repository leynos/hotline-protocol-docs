
void FUN_1002f0c0(byte *param_1,int param_2)

{
  bool bVar1;
  byte bVar2;
  short sVar3;
  
  if (param_1 == (byte *)0x0) {
    return;
  }
  if (param_2 == 0) {
    return;
  }
  sVar3 = FUN_1002a9f0();
  if (sVar3 < 0xa00) {
    while (bVar1 = param_2 != 0, param_2 = param_2 + -1, bVar1) {
      if (*param_1 == 0x3a) {
        *param_1 = 0x2d;
      }
      param_1 = param_1 + 1;
    }
    return;
  }
  if (*param_1 == 0x2e) {
    *param_1 = 0x2d;
  }
  if (param_2 == 1) {
    bVar2 = *param_1;
    if (bVar2 != 0x5c) {
      if (bVar2 < 0x5c) {
        if (bVar2 != 0x3f) {
          if (bVar2 < 0x3f) {
            if ((0x29 < bVar2) || (bVar2 < 0x28)) goto LAB_1002f1b8;
          }
          else if (bVar2 < 0x5b) goto LAB_1002f1b8;
        }
      }
      else {
        if (bVar2 == 0x7c) goto LAB_1002f1b8;
        if (bVar2 < 0x7c) {
          if ((bVar2 < 0x7b) && (0x5d < bVar2)) goto LAB_1002f1b8;
        }
        else if (0x7e < bVar2) goto LAB_1002f1b8;
      }
      *param_1 = 0x2d;
    }
  }
LAB_1002f1b8:
  while (bVar1 = param_2 != 0, param_2 = param_2 + -1, bVar1) {
    bVar2 = *param_1;
    if ((bVar2 == 0x3a) || ((bVar2 < 0x3a && (bVar2 == 0x2f)))) {
      *param_1 = 0x2d;
    }
    param_1 = param_1 + 1;
  }
  return;
}

