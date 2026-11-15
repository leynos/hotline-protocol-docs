
void FUN_10027a20(undefined4 param_1,short *param_2)

{
  char cVar2;
  undefined4 uVar1;
  undefined1 local_310;
  undefined1 auStack_30f [127];
  undefined1 local_290;
  undefined1 auStack_28f [127];
  undefined1 local_210;
  undefined1 auStack_20f [255];
  undefined1 local_110;
  undefined1 auStack_10f [255];
  
  local_290 = FUN_10057e30(auStack_28f,0x7f,0x21);
  local_210 = FUN_10027d40(param_2,auStack_20f,0xff);
  if ((*(int *)(param_2 + 2) == 0) || (**(char **)(param_2 + 2) == '\0')) {
    if (*(int *)(param_2 + 6) == 0) {
      local_310 = FUN_10054180(auStack_30f,0x7f,s_ID__hi__hi_100938e0,(int)*param_2,(int)param_2[1])
      ;
    }
    else {
      local_310 = FUN_10054180(auStack_30f,0x7f,0x100938eb,(int)*param_2,(int)param_2[1],
                               *(undefined4 *)(param_2 + 6));
    }
  }
  else if (*(int *)(param_2 + 6) == 0) {
    local_310 = FUN_10054180(auStack_30f,0x7f,s_ID__hi__hi____s___lu_100938fc,(int)*param_2,
                             (int)param_2[1],*(undefined4 *)(param_2 + 2),
                             *(undefined4 *)(param_2 + 4));
  }
  else {
    local_310 = FUN_10054180(auStack_30f,0x7f,s_ID__hi__hi___li_____s___lu_10093911,(int)*param_2,
                             (int)param_2[1],*(undefined4 *)(param_2 + 6),
                             *(undefined4 *)(param_2 + 2),*(undefined4 *)(param_2 + 4));
  }
  local_110 = FUN_10054180(auStack_10f,0xff,0x1009392c,&local_290,&local_210,&local_310);
  cVar2 = FUN_1002b750(param_1,0);
  if (cVar2 == '\0') {
    FUN_1002b370(param_1,0x54455854,0x74747874);
  }
  FUN_1002c220(param_1,0x23);
  uVar1 = FUN_1002c4d0(param_1,0);
  FUN_1002c440(param_1,uVar1,auStack_10f,local_110,0);
  FUN_1002c2c0(param_1);
  return;
}

