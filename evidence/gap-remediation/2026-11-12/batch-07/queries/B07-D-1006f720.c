
undefined4 * FUN_1006f720(undefined4 param_1,undefined4 param_2)

{
  bool bVar1;
  short sVar4;
  undefined4 *puVar2;
  undefined4 uVar3;
  int local_7c;
  
  if (-1 < (char)bRam10096bd8) {
    if ((bRam10096bd8 >> 6 & 1) == 0) {
      .glue::Gestalt(0x6f74616e,0x10096bcc);
      .glue::Gestalt(0x6f747672,0x10096bd0);
      bRam10096bd8 = bRam10096bd8 & 0xbf | 0x40;
    }
    bVar1 = false;
    if ((uRam10096bcc & 1) != 0) {
      if (0x110ffff < iRam10096bd0) {
        bVar1 = true;
      }
    }
    if (!bVar1) {
      FUN_10027c30(8,0x6e);
    }
    sVar4 = .glue::InitOpenTransportInContext(1,0);
    FUN_10073730((int)sVar4);
    FUN_1002ab10(*(undefined4 *)(local_7c + -0x7398));
    *(undefined4 *)(local_7c + 0x5e6c) = *(undefined4 *)(local_7c + -0x739c);
    bRam10096bd8 = bRam10096bd8 & 0x7f | 0x80;
  }
  puVar2 = (undefined4 *)FUN_10052b70(0x60);
  puVar2[3] = param_1;
  puVar2[4] = param_2;
  uVar3 = FUN_10071d50(puVar2,0);
  puVar2[1] = uVar3;
  *puVar2 = puRam10096bd4;
  puRam10096bd4 = puVar2;
  return puVar2;
}

