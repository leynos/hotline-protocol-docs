
undefined4 FUN_10070790(int param_1)

{
  char cVar2;
  int iVar1;
  undefined4 uVar3;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  uVar3 = 0;
  cVar2 = .glue::OTAtomicTestBit(param_1 + 0x5e,1);
  if ((cVar2 != '\0') ||
     (iVar1 = .glue::OTGetEndpointState(*(undefined4 *)(param_1 + 4)), iVar1 == 6)) {
    uVar3 = 1;
  }
  return uVar3;
}

