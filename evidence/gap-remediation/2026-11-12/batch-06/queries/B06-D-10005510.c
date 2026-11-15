
void FUN_10005510(int param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar1;
  undefined4 *puVar2;
  
  for (puVar2 = *(undefined4 **)(param_1 + 0x34); puVar2 != (undefined4 *)0x0;
      puVar2 = (undefined4 *)*puVar2) {
    cVar1 = FUN_10058600(puVar2[1]);
    if ((cVar1 != '\0') && (*(char *)((int)puVar2 + 0x14a) < '\0')) {
      FUN_10058ca0(puVar2[1],param_2,param_3);
    }
  }
  return;
}

