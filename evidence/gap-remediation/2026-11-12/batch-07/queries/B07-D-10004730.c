
undefined4 * FUN_10004730(int param_1,short param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0x34);
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    if (*(short *)(puVar1 + 5) == param_2) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  return puVar1;
}

