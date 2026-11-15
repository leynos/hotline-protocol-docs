
undefined4 * FUN_1006d340(undefined4 param_1,char param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)FUN_10052b70(8);
  *(char *)(puVar1 + 1) = param_2;
  if (param_2 == '\0') {
    uVar2 = FUN_100738b0(param_1,param_3);
    *puVar1 = uVar2;
  }
  else {
    uVar2 = FUN_1006f720(param_1,param_3);
    *puVar1 = uVar2;
  }
  return puVar1;
}

