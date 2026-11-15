
void FUN_10018620(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  uVar1 = FUN_10056b90(param_4,0x72);
  iVar2 = FUN_10004760(param_1,uVar1);
  if ((iVar2 != 0) && (iVar3 = FUN_10055630(iVar2 + 4,param_2), iVar3 != 0)) {
    if (*(int *)(iVar2 + 8) == 0) {
      FUN_10055b20(param_1 + 0x420,iVar2);
      FUN_10052c10(*(undefined4 *)(iVar2 + 0x14));
      if (iVar2 != 0) {
        if (iVar2 != -4) {
          FUN_10055480(iVar2 + 4,0);
        }
        FUN_1006d290(iVar2);
      }
    }
    else {
      uVar4 = FUN_10056380(0,0);
      FUN_10056a90(uVar4,0x72,uVar1);
      FUN_10056a90(uVar4,0x67,*(undefined2 *)(param_2 + 0x14));
      FUN_100048b0(param_1,iVar2,0x76,uVar4);
      FUN_100563d0(uVar4);
    }
  }
  return;
}

