
void FUN_1007c270(undefined1 *param_1,byte *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = (uint)*param_2;
  if (param_3 < *param_2) {
    uVar2 = param_3;
  }
  *param_1 = (char)uVar2;
  for (uVar1 = 1; uVar1 <= uVar2; uVar1 = uVar1 + 1) {
    param_1[uVar1] = param_2[uVar1];
  }
  return;
}

