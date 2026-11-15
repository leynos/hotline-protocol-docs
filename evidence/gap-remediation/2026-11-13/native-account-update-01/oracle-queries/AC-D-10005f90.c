
void FUN_10005f90(int param_1,char *param_2,int param_3)

{
  undefined4 uVar1;
  short sVar3;
  undefined4 uVar2;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined1 local_128;
  undefined1 auStack_127 [275];
  
  if (((param_2 != (char *)0x0) && (*param_2 != '\0')) && (param_3 != 0)) {
    uVar1 = FUN_10056380(0,0);
    FUN_10056ae0(uVar1,0x65,0x1008fd66);
    for (puVar5 = *(undefined4 **)(param_1 + 0x34); puVar5 != (undefined4 *)0x0;
        puVar5 = (undefined4 *)*puVar5) {
      sVar3 = FUN_1006d180((int)puVar5 + 0x79,*(undefined1 *)(puVar5 + 0x1e),param_2 + 1,*param_2);
      if (sVar3 == 0) {
        FUN_10058ca0(puVar5[1],0x68,uVar1);
        FUN_10058400(puVar5[1]);
        FUN_10028dc0(100,0,0,0,0,0,0);
        puVar4 = puVar5 + 0xe;
        if (*(char *)(puVar5 + 0xe) == '\0') {
          uVar2 = FUN_10058270(puVar5[1]);
          local_128 = FUN_1006d550(uVar2,auStack_127,0xff);
          puVar4 = (undefined4 *)&local_128;
        }
        FUN_100068e0(param_1,param_3,0x1008fd9b,puVar4);
      }
    }
    FUN_100563d0(uVar1);
  }
  return;
}

