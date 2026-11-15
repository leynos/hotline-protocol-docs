
void FUN_10006590(int param_1)

{
  bool bVar1;
  undefined4 uVar2;
  char cVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined1 local_128;
  undefined1 auStack_127 [275];
  
  uVar2 = FUN_10056380(0,0);
  FUN_10056ae0(uVar2,0x65,0x1008fdac);
  puVar7 = *(undefined4 **)(param_1 + 0x34);
  do {
    if (puVar7 == (undefined4 *)0x0) {
      FUN_100563d0(uVar2);
      return;
    }
    uVar5 = puVar7[4];
    uVar6 = 0;
    do {
      uVar6 = uVar6 + 1;
      if (*(uint *)(param_1 + 0x44c) < uVar6) {
        bVar1 = false;
        goto LAB_10006640;
      }
      cVar3 = FUN_10009960(*(undefined4 *)(*(int *)(param_1 + 0x448) + uVar6 * 4 + -4),uVar5);
    } while (cVar3 == '\0');
    bVar1 = true;
LAB_10006640:
    if (bVar1) {
      FUN_10058ca0(puVar7[1],0x68,uVar2);
      FUN_10058400(puVar7[1]);
      FUN_10028dc0(100,0,0,0,0,0,0);
      puVar4 = puVar7 + 0xe;
      if (*(char *)(puVar7 + 0xe) == '\0') {
        uVar5 = FUN_10058270(puVar7[1]);
        local_128 = FUN_1006d550(uVar5,auStack_127,0xff);
        puVar4 = (undefined4 *)&local_128;
      }
      FUN_100068e0(param_1,puVar7,0x1008fdd7,puVar4);
    }
    puVar7 = (undefined4 *)*puVar7;
  } while( true );
}

