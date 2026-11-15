
undefined4 FUN_10053a60(undefined4 param_1,uint param_2,undefined4 param_3,uint param_4)

{
  undefined4 uVar1;
  
  if (param_2 < param_4) {
    uVar1 = 0xffffffff;
  }
  else if (param_4 < param_2) {
    uVar1 = 1;
  }
  else {
    uVar1 = FUN_10053ac0(param_1,param_3,param_2,0);
  }
  return uVar1;
}

