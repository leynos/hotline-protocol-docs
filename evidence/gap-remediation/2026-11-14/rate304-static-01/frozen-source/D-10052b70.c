
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_10052b70(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (_DAT_10089418 == 0) {
    FUN_10079c60(&DAT_10096b50);
    _DAT_10089418 = 1;
  }
  iVar1 = FUN_10079e30(&DAT_10096b50,param_1);
  if (iVar1 == 0) {
    FUN_10027c30(3,0x65);
  }
  return iVar1;
}

