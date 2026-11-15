
void FUN_10004790(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  for (puVar1 = *(undefined4 **)(param_1 + 0x420); puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
    if (puVar1[4] == param_2) goto LAB_100047d8;
  }
  puVar1 = (undefined4 *)0x0;
LAB_100047d8:
  if (puVar1 != (undefined4 *)0x0) {
    uVar2 = FUN_10056380(0,0);
    FUN_10056a90(uVar2,0x72,param_2);
    FUN_100568b0(uVar2,0x65,param_3,param_4);
    iVar7 = puVar1[1];
    iVar6 = puVar1[2];
    for (iVar5 = 0; iVar5 != iVar6; iVar5 = iVar5 + 1) {
      iVar4 = *(int *)(iVar7 + iVar5 * 4);
      cVar3 = FUN_10058600(*(undefined4 *)(iVar4 + 4));
      if ((cVar3 != '\0') && (cVar3 = FUN_10008a90(param_1,iVar4,9), cVar3 != '\0')) {
        FUN_10058ca0(*(undefined4 *)(iVar4 + 4),0x6a,uVar2);
      }
    }
    FUN_100563d0(uVar2);
  }
  return;
}

