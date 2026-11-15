
void FUN_10004bf0(undefined4 param_1,int param_2,byte *param_3,int param_4)

{
  undefined1 uVar1;
  byte bVar2;
  
  if (((param_2 != 0) && (param_3 != (byte *)0x0)) && (*param_3 != 0)) {
    *(undefined8 *)(param_2 + 8) = *(undefined8 *)(param_4 + 4);
    bVar2 = *param_3;
    if (0x1f < bVar2) {
      bVar2 = 0x1f;
    }
    if (bVar2 == 0) {
      uVar1 = FUN_100539c0(param_2 + 0x19,0x1008fd2d,3);
      *(undefined1 *)(param_2 + 0x18) = uVar1;
    }
    else {
      uVar1 = FUN_100539c0(param_2 + 0x19,param_3 + 1,bVar2);
      *(undefined1 *)(param_2 + 0x18) = uVar1;
      FUN_10054210(param_2 + 0x19,uVar1,0,0x2a,1);
    }
    if ((*(byte *)(param_2 + 0xb) >> 5 & 1) == 0) {
      if (*(short *)(param_4 + 0x210) == 0) {
        uVar1 = FUN_100539c0(param_2 + 0x39,0x1008fd2d,3);
        *(undefined1 *)(param_2 + 0x38) = uVar1;
      }
      else {
        uVar1 = FUN_100539c0(param_2 + 0x39,param_4 + 0x212,*(short *)(param_4 + 0x210));
        *(undefined1 *)(param_2 + 0x38) = uVar1;
      }
    }
    else {
      FUN_100539c0(param_2 + 0x38,param_2 + 0x18,*(byte *)(param_2 + 0x18) + 1);
    }
    FUN_10004f30(param_1,param_2);
  }
  return;
}

