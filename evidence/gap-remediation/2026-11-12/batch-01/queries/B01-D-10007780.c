
/* WARNING: Removing unreachable block (ram,0x1000789c) */

undefined4 FUN_10007780(int param_1,char *param_2,byte *param_3,char param_4)

{
  bool bVar1;
  undefined4 uVar2;
  byte bVar4;
  byte *pbVar3;
  uint uVar5;
  undefined1 auStack_530 [128];
  byte local_44f [75];
  undefined1 *local_404;
  undefined1 local_400;
  undefined1 auStack_3ff [255];
  undefined2 local_300 [2];
  undefined1 auStack_2fc [660];
  ushort local_68;
  undefined1 auStack_66 [34];
  undefined2 local_44;
  undefined1 auStack_42 [38];
  
  if ((param_2 == (char *)0x0) || (*param_2 == '\0')) {
    uVar2 = 0;
  }
  else {
    FUN_100073c0(param_1,param_2,local_300);
    local_300[0] = 1;
    if ((param_3 != (byte *)0x0) && (*param_3 != 0)) {
      if (*param_3 < 0x20) {
        bVar4 = *param_3;
      }
      else {
        bVar4 = 0x1f;
      }
      bVar4 = FUN_100539c0(local_44f,param_3 + 1,bVar4);
      uVar5 = (uint)bVar4;
      pbVar3 = local_44f;
      while (bVar1 = uVar5 != 0, uVar5 = uVar5 - 1, bVar1) {
        *pbVar3 = ~*pbVar3;
        pbVar3 = pbVar3 + 1;
      }
      local_44 = FUN_100539c0(auStack_42,local_44f,bVar4);
    }
    if (param_4 != '\0') {
      FUN_10007ed0(auStack_2fc);
      FUN_10007e80(auStack_2fc,2,1);
      FUN_10007e80(auStack_2fc,0x27,1);
      FUN_10007e80(auStack_2fc,1,1);
      FUN_10007e80(auStack_2fc,0x26,1);
      FUN_10007e80(auStack_2fc,0x19,1);
      FUN_10007e80(auStack_2fc,0,1);
      FUN_10007e80(auStack_2fc,3,1);
      FUN_10007e80(auStack_2fc,4,1);
      FUN_10007e80(auStack_2fc,0x1c,1);
      FUN_10007e80(auStack_2fc,5,1);
      FUN_10007e80(auStack_2fc,6,1);
      FUN_10007e80(auStack_2fc,7,1);
      FUN_10007e80(auStack_2fc,8,1);
      FUN_10007e80(auStack_2fc,0x1d,1);
      FUN_10007e80(auStack_2fc,0x1e,1);
      FUN_10007e80(auStack_2fc,0x1f,1);
      FUN_10007e80(auStack_2fc,0xe,1);
      FUN_10007e80(auStack_2fc,0xf,1);
      FUN_10007e80(auStack_2fc,0x10,1);
      FUN_10007e80(auStack_2fc,0x11,1);
      FUN_10007e80(auStack_2fc,0x18,1);
      FUN_10007e80(auStack_2fc,0x16,1);
      FUN_10007e80(auStack_2fc,0x17,1);
      FUN_10007e80(auStack_2fc,0x28,1);
      FUN_10007e80(auStack_2fc,0x20,1);
      FUN_10007e80(auStack_2fc,0x14,1);
      FUN_10007e80(auStack_2fc,0x15,1);
      FUN_10007e80(auStack_2fc,0x21,1);
      FUN_10007e80(auStack_2fc,0x22,1);
      FUN_10007e80(auStack_2fc,0x23,1);
      FUN_10007e80(auStack_2fc,0x24,1);
      FUN_10007e80(auStack_2fc,0x25,1);
      FUN_10007e80(auStack_2fc,0xb,1);
      FUN_10007e80(auStack_2fc,9,1);
      FUN_10007e80(auStack_2fc,10,1);
      FUN_10007e80(auStack_2fc,0x1a,1);
    }
    if (*(int *)(param_1 + 0xb0) != 0) {
      local_400 = (undefined1)local_68;
      local_404 = auStack_530 + 0x80;
      FUN_100539c0(auStack_3ff,auStack_66,local_68 & 0xff);
      uVar2 = FUN_1002af80(*(undefined4 *)(param_1 + 0xb0),&local_400,0x1008fed3,0x2a0,0);
      FUN_1002c220(uVar2,0x23);
      FUN_1002c5a0(uVar2,0x2de);
      FUN_1002c440(uVar2,0,local_300,0x2de,0);
      FUN_1002b2f0(uVar2);
    }
    uVar2 = 1;
  }
  return uVar2;
}

