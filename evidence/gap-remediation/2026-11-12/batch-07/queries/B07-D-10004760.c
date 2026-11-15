
undefined4 * FUN_10004760(int param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0x420);
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    if (puVar1[4] == param_2) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  return puVar1;
}

