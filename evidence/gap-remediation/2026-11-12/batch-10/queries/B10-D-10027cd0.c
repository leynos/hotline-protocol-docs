
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_10027cd0(void)

{
  int iVar1;
  int local_2c;
  
  if (_DAT_100893e4 == 0) {
    iVar1 = .glue::GetNewDialog(0x24dd,0,0xffffffff);
    *(int *)(local_2c + -0x733c) = iVar1;
    if (iVar1 == 0) {
      FUN_10001bd0(local_2c + 0x322c);
      .glue::SysBeep(0x14);
      .glue::SysBeep(0x14);
      .glue::ExitToShell();
    }
  }
  return;
}

