
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_10000050(void)

{
  char cVar2;
  int iVar1;
  
  FUN_1002a8d0();
  FUN_1006d310();
  cVar2 = FUN_1006d2e0();
  if (cVar2 == '\0') {
    FUN_10027c30(8,0x6d);
  }
  _DAT_10096af6 = 0x80;
  iVar1 = FUN_1006d260(0xab0);
  if (iVar1 != 0) {
    FUN_10000160(iVar1);
  }
  _DAT_10096074 = iVar1;
  FUN_100007b0(iVar1);
  FUN_10082630();
  if (_DAT_10096074 != 0) {
    FUN_10082630(_DAT_10096074,1);
  }
  return;
}

