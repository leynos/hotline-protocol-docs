
void FUN_10058df0(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  if (param_2 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
    for (puVar2 = *(undefined4 **)(param_1 + 0x10); puVar2 != (undefined4 *)0x0;
        puVar2 = (undefined4 *)*puVar2) {
      if (puVar2 == param_2) {
        if (puVar1 == (undefined4 *)0x0) {
          *(undefined4 *)(param_1 + 0x10) = *puVar2;
        }
        else {
          *puVar1 = *puVar2;
        }
        break;
      }
      puVar1 = puVar2;
    }
    FUN_10052e90(param_2[1]);
    FUN_10052c10(param_2);
  }
  return;
}

