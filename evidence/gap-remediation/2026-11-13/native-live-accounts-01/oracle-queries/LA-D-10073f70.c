
void FUN_10073f70(int *param_1)

{
  char cVar1;
  
  if (param_1 == (int *)0x0) {
    FUN_10027c30(1,2);
  }
  if (*(char *)((int)param_1 + 0xe) == '\0') {
    *(undefined1 *)((int)param_1 + 0xe) = 1;
    if ((*param_1 != 0) && (cVar1 = FUN_10070300(*param_1), cVar1 != '\0')) {
      FUN_100767f0(*param_1);
      *param_1 = 0;
    }
    if ((param_1[1] != 0) && (cVar1 = FUN_10070300(param_1[1]), cVar1 != '\0')) {
      FUN_10076790(param_1[1]);
      param_1[1] = 0;
    }
    if (param_1 == (int *)0x0) {
      FUN_10027c30(1,2);
    }
    if (param_1[4] != 0) {
      FUN_10028dc0(0x67,0,0,0,param_1[4],param_1[5],param_1[6]);
    }
  }
  return;
}

