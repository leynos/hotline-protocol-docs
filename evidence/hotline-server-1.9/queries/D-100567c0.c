
undefined2 FUN_100567c0(undefined4 *param_1,undefined4 param_2)

{
  char cVar2;
  undefined2 uVar1;
  int local_20 [7];
  
  cVar2 = FUN_100572d0(param_1,param_2,local_20);
  if (cVar2 == '\0') {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_10053910(*param_1,local_20[0] + 2);
  }
  return uVar1;
}

