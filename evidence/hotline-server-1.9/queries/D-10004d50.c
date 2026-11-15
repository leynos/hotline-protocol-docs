
void FUN_10004d50(undefined4 param_1,int param_2,undefined4 param_3,int param_4)

{
  undefined1 uVar4;
  undefined2 uVar3;
  uint uVar1;
  int iVar2;
  ushort uVar5;
  
  if (param_2 != 0) {
    if (param_4 != 0) {
      *(undefined8 *)(param_2 + 8) = *(undefined8 *)(param_4 + 4);
    }
    FUN_10056c70(param_3,0x66,param_2 + 0x18,0x20);
    if (*(char *)(param_2 + 0x18) == '\0') {
      uVar4 = FUN_100539c0(param_2 + 0x19,0x1008fd2d,3);
      *(undefined1 *)(param_2 + 0x18) = uVar4;
    }
    else {
      FUN_10054210(param_2 + 0x19,*(undefined1 *)(param_2 + 0x18),0,0x2a,1);
    }
    if ((*(byte *)(param_2 + 0xb) >> 5 & 1) == 0) {
      if (param_4 != 0) {
        uVar5 = *(ushort *)(param_4 + 0x210);
        if (0x1f < uVar5) {
          uVar5 = 0x1f;
        }
        if (uVar5 == 0) {
          uVar4 = FUN_100539c0(param_2 + 0x39,0x1008fd2d,3);
          *(undefined1 *)(param_2 + 0x38) = uVar4;
        }
        else {
          uVar4 = FUN_100539c0(param_2 + 0x39,param_4 + 0x212,uVar5);
          *(undefined1 *)(param_2 + 0x38) = uVar4;
        }
      }
    }
    else {
      FUN_100539c0(param_2 + 0x38,param_2 + 0x18,*(byte *)(param_2 + 0x18) + 1);
    }
    uVar3 = FUN_10056b90(param_3,0x68);
    *(undefined2 *)(param_2 + 0x16) = uVar3;
    uVar1 = FUN_10056b90(param_3,0x71);
    *(byte *)(param_2 + 0xb0) = (byte)uVar1 & 1;
    *(byte *)(param_2 + 0xb1) = (byte)(uVar1 >> 1) & 1;
    uVar1 = uVar1 >> 2 & 1;
    *(char *)(param_2 + 0xb2) = (char)uVar1;
    *(undefined1 *)(param_2 + 0xb3) = 0;
    if (uVar1 != 0) {
      iVar2 = FUN_100567c0(param_3,0xd7);
      if (iVar2 == 0) {
        uVar4 = FUN_10054180(param_2 + 0xb4,0x7f,s_I_m_not_able_to_respond_right_no_1008fd31);
        *(undefined1 *)(param_2 + 0xb3) = uVar4;
      }
      else {
        FUN_10056c70(param_3,0xd7,param_2 + 0xb3,0x80);
      }
    }
    FUN_10004f30(param_1,param_2);
  }
  return;
}

