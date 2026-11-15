
int FUN_10054310(byte *param_1,int param_2,char *param_3,uint *param_4)

{
  char *pcVar1;
  char cVar2;
  byte bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  bool bVar9;
  bool bVar10;
  bool bVar11;
  uint uVar12;
  char *pcVar13;
  byte *pbVar14;
  int *piVar15;
  byte *pbVar16;
  int iVar17;
  uint uVar18;
  int iVar19;
  byte local_222;
  uint local_220;
  uint local_21c;
  byte abStack_19 [21];
  
  iVar17 = 0;
  cVar2 = *param_3;
  while( true ) {
    iVar19 = (int)cVar2;
    if (iVar19 == 0) {
      return iVar17;
    }
    if (iVar19 == 0x25) break;
LAB_100549b8:
    *param_1 = (byte)iVar19;
    iVar17 = iVar17 + 1;
    param_1 = param_1 + 1;
    if (iVar17 == param_2) {
      return iVar17;
    }
LAB_10054a70:
    param_3 = param_3 + 1;
    cVar2 = *param_3;
  }
  bVar11 = false;
  bVar10 = false;
  bVar6 = false;
  bVar5 = false;
  local_222 = 0;
  local_220 = 0;
  local_21c = 0;
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            pcVar13 = param_3 + 1;
            iVar19 = (int)*pcVar13;
            if (iVar19 != 0x2d) break;
            bVar5 = true;
            param_3 = pcVar13;
          }
          if (iVar19 != 0x2b) break;
          bVar6 = true;
          param_3 = pcVar13;
        }
        if (iVar19 != 0x20) break;
        local_222 = 0x20;
        param_3 = pcVar13;
      }
      if (iVar19 != 0x23) break;
      bVar11 = true;
      param_3 = pcVar13;
    }
    if (iVar19 != 0x30) break;
    bVar10 = true;
    param_3 = pcVar13;
  }
  if (iVar19 == 0x2a) {
    local_220 = *param_4;
    param_4 = param_4 + 1;
    if ((int)local_220 < 0) {
      bVar5 = true;
      local_220 = -local_220;
    }
    pcVar13 = param_3 + 2;
    iVar19 = (int)*pcVar13;
  }
  else {
    while ((0x2f < iVar19 && (iVar19 < 0x3a))) {
      local_220 = (iVar19 + local_220 * 10) - 0x30;
      pcVar1 = pcVar13 + 1;
      pcVar13 = pcVar13 + 1;
      iVar19 = (int)*pcVar1;
    }
  }
  bVar9 = false;
  param_3 = pcVar13;
  if (iVar19 == 0x2e) {
    param_3 = pcVar13 + 1;
    iVar19 = (int)*param_3;
    if (iVar19 == 0x2a) {
      local_21c = *param_4;
      param_3 = pcVar13 + 2;
      iVar19 = (int)*param_3;
      param_4 = param_4 + 1;
    }
    else {
      while ((0x2f < iVar19 && (iVar19 < 0x3a))) {
        local_21c = (iVar19 + local_21c * 10) - 0x30;
        pcVar13 = param_3 + 1;
        param_3 = param_3 + 1;
        iVar19 = (int)*pcVar13;
      }
    }
    if (-1 < (int)local_21c) {
      bVar9 = true;
    }
  }
  bVar8 = false;
  bVar7 = false;
  pbVar16 = abStack_19 + 1;
  bVar4 = false;
  if (bVar5) {
    bVar10 = false;
    bVar8 = false;
    bVar7 = false;
    bVar4 = true;
  }
LAB_10054508:
  switch(iVar19) {
  case 0x25:
    goto LAB_100549b8;
  default:
    return iVar17;
  case 0x4c:
    param_3 = param_3 + 1;
    iVar19 = (int)*param_3;
    goto LAB_10054508;
  case 99:
    pbVar16 = abStack_19;
    uVar18 = 1;
    goto LAB_100549d0;
  case 100:
  case 0x69:
    if (bVar7) {
      uVar12 = *param_4;
    }
    else {
      uVar12 = *param_4;
    }
    if (bVar8) {
      uVar12 = (uint)(short)uVar12;
    }
    if ((int)uVar12 < 0) {
      uVar12 = -uVar12;
      local_222 = 0x2d;
    }
    else if (bVar6) {
      local_222 = 0x2b;
    }
    goto code_r0x10054614;
  case 0x68:
    bVar8 = true;
    param_3 = param_3 + 1;
    iVar19 = (int)*param_3;
    goto LAB_10054508;
  case 0x6c:
    goto code_r0x10054544;
  case 0x6e:
    piVar15 = (int *)*param_4;
    param_4 = param_4 + 1;
    if (bVar8) {
      *(short *)piVar15 = (short)iVar17;
    }
    else if (bVar7) {
      *piVar15 = iVar17;
    }
    else {
      *piVar15 = iVar17;
    }
    goto LAB_10054a70;
  case 0x6f:
    if (bVar7) {
      uVar12 = *param_4;
    }
    else {
      uVar12 = *param_4;
    }
    if (bVar8) {
      uVar12 = uVar12 & 0xffff;
    }
    if (!bVar9) {
      if (bVar10) {
        local_21c = local_220;
      }
      if ((int)local_21c < 1) {
        local_21c = 1;
      }
    }
    uVar18 = 0;
    for (; uVar12 != 0; uVar12 = uVar12 >> 3) {
      pbVar16 = pbVar16 + -1;
      *pbVar16 = ((byte)uVar12 & 7) + 0x30;
      uVar18 = uVar18 + 1;
    }
    if (((bVar11) && (uVar18 != 0)) && (*pbVar16 != 0x30)) {
      pbVar16 = pbVar16 + -1;
      *pbVar16 = 0x30;
      uVar18 = uVar18 + 1;
    }
    for (; (int)uVar18 < (int)local_21c; uVar18 = uVar18 + 1) {
      pbVar16 = pbVar16 + -1;
      *pbVar16 = 0x30;
    }
    goto LAB_100549d0;
  case 0x70:
    bVar9 = true;
    bVar7 = true;
    local_21c = 8;
  case 0x58:
    pcVar13 = s_0123456789ABCDEF_10094948;
    break;
  case 0x73:
    pbVar16 = (byte *)*param_4;
    if (bVar11) {
      uVar18 = (uint)*pbVar16;
      pbVar16 = pbVar16 + 1;
      if ((bVar9) && ((int)local_21c < (int)uVar18)) {
        uVar18 = local_21c;
      }
    }
    else if (bVar9) {
      uVar18 = 0;
      if (pbVar16 != (byte *)0x0) {
        pbVar14 = pbVar16;
        for (; (bVar3 = *pbVar14, pbVar14 = pbVar14 + 1, bVar3 != 0 && (uVar18 != local_21c));
            uVar18 = uVar18 + 1) {
        }
      }
    }
    else {
      uVar18 = 0;
      if (pbVar16 != (byte *)0x0) {
        pbVar14 = pbVar16;
        while (bVar3 = *pbVar14, pbVar14 = pbVar14 + 1, bVar3 != 0) {
          uVar18 = uVar18 + 1;
        }
      }
    }
    goto LAB_100549d0;
  case 0x75:
    if (bVar7) {
      uVar12 = *param_4;
    }
    else {
      uVar12 = *param_4;
    }
    if (bVar8) {
      uVar12 = uVar12 & 0xffff;
    }
    local_222 = 0;
code_r0x10054614:
    if (!bVar9) {
      if ((bVar10) && (local_21c = local_220, local_222 != 0)) {
        local_21c = local_220 - 1;
      }
      if ((int)local_21c < 1) {
        local_21c = 1;
      }
    }
    uVar18 = 0;
    for (; uVar12 != 0; uVar12 = uVar12 / 10) {
      pbVar16 = pbVar16 + -1;
      *pbVar16 = (char)uVar12 + (char)(uVar12 / 10) * -10 + 0x30;
      uVar18 = uVar18 + 1;
    }
    for (; (int)uVar18 < (int)local_21c; uVar18 = uVar18 + 1) {
      pbVar16 = pbVar16 + -1;
      *pbVar16 = 0x30;
    }
    if (local_222 != 0) {
      pbVar16 = pbVar16 + -1;
      *pbVar16 = local_222;
      uVar18 = uVar18 + 1;
    }
    goto LAB_100549d0;
  case 0x78:
    pcVar13 = s_0123456789abcdef_10094959;
  }
  if (bVar7) {
    uVar12 = *param_4;
  }
  else {
    uVar12 = *param_4;
  }
  if (bVar8) {
    uVar12 = uVar12 & 0xffff;
  }
  if (!bVar9) {
    if ((bVar10) && (local_21c = local_220, bVar11)) {
      local_21c = local_220 - 2;
    }
    if ((int)local_21c < 1) {
      local_21c = 1;
    }
  }
  uVar18 = 0;
  for (; uVar12 != 0; uVar12 = uVar12 >> 4) {
    pbVar16 = pbVar16 + -1;
    *pbVar16 = pcVar13[uVar12 & 0xf];
    uVar18 = uVar18 + 1;
  }
  for (; (int)uVar18 < (int)local_21c; uVar18 = uVar18 + 1) {
    pbVar16 = pbVar16 + -1;
    *pbVar16 = 0x30;
  }
  if (bVar11) {
    pbVar16[-1] = (byte)iVar19;
    pbVar16 = pbVar16 + -2;
    *pbVar16 = 0x30;
    uVar18 = uVar18 + 2;
  }
LAB_100549d0:
  param_4 = param_4 + 1;
  if (((int)uVar18 < (int)local_220) && (!bVar4)) {
    do {
      *param_1 = 0x20;
      iVar17 = iVar17 + 1;
      param_1 = param_1 + 1;
      if (iVar17 == param_2) {
        return iVar17;
      }
      local_220 = local_220 - 1;
    } while ((int)uVar18 < (int)local_220);
  }
  for (iVar19 = 0; iVar19 < (int)uVar18; iVar19 = iVar19 + 1) {
    *param_1 = *pbVar16;
    iVar17 = iVar17 + 1;
    pbVar16 = pbVar16 + 1;
    param_1 = param_1 + 1;
    if (iVar17 == param_2) {
      return iVar17;
    }
  }
  for (; (int)uVar18 < (int)local_220; uVar18 = uVar18 + 1) {
    *param_1 = 0x20;
    iVar17 = iVar17 + 1;
    param_1 = param_1 + 1;
    if (iVar17 == param_2) {
      return iVar17;
    }
  }
  goto LAB_10054a70;
code_r0x10054544:
  bVar7 = true;
  param_3 = param_3 + 1;
  iVar19 = (int)*param_3;
  goto LAB_10054508;
}

