
undefined4 FUN_10023830(int param_1,uint param_2,char param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_40c;
  int local_408;
  int local_404 [2];
  undefined1 auStack_3fc [36];
  uint local_3d8;
  int local_3d4;
  int local_3d0;
  int local_3cc;
  int local_3c8 [44];
  undefined1 auStack_318 [40];
  int local_2f0;
  int local_2ec;
  int local_2e8;
  int local_2e4;
  int local_230;
  int local_22c;
  uint local_210;
  int local_20c;
  uint local_208;
  int local_204;
  int local_200;
  int local_1fc;
  undefined1 auStack_1f4 [12];
  int local_1e8;
  uint local_1e4;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002c220(param_1,0x23);
  iVar1 = FUN_1002c3b0(param_1,0,&local_230,0x17c,0);
  if (iVar1 != 0x17c) {
    FUN_10027c30(1,9);
  }
  if (local_230 != 0x484c4e5a) {
    FUN_10027c30(1,8);
  }
  if (local_22c != 2) {
    FUN_10027c30(1,7);
  }
  local_40c = local_204;
  iVar1 = (local_1e4 + 1) * 8;
  iVar5 = local_210 * (local_1e8 + -1) + 0x200;
  local_408 = FUN_10052a10(iVar1);
  FUN_1002c3b0(param_1,iVar5,local_408,iVar1,0);
  iVar4 = local_408;
  iVar2 = FUN_10024280(param_1,local_210,param_2,local_408 + (param_2 & local_1e4) * 8);
  if (iVar2 == 0) {
    FUN_10027c30(1,0xc);
  }
  iVar3 = FUN_1002c3b0(param_1,(iVar2 + -1) * local_210 + 0x200,auStack_3fc,0xe4,0);
  if (iVar3 != 0xe4) {
    FUN_10027c30(1,9);
  }
  if (param_3 != '\0') {
    FUN_100249f0(param_1,local_210,auStack_1f4,iVar4,local_1e4,local_3c8[0],&local_40c);
  }
  FUN_10025060(param_1,local_210,auStack_1f4,iVar2);
  FUN_10024620(param_1,local_210,iVar4 + (local_3d8 & local_1e4) * 8,local_3d8,auStack_1f4);
  local_40c = local_40c + -1;
  if ((param_3 == '\0') && (local_3c8[0] != 0)) {
    iVar4 = FUN_1002c3b0(param_1,local_210 * (local_3c8[0] + -1) + 0x200,auStack_318,0xe4,0);
    if (iVar4 != 0xe4) {
      FUN_10027c30(1,9);
    }
    if (local_3d4 == 0) {
      if (local_3cc == 0) {
        local_200 = local_3c8[0];
      }
      else {
        FUN_1002c440(param_1,local_210 * (local_3cc + -1) + 0x234,local_3c8,4,0);
      }
    }
    else {
      FUN_1002c440(param_1,local_210 * (local_3d4 + -1) + 0x22c,local_3c8,4,0);
    }
    if (local_3d0 == 0) {
      if (local_3cc == 0) {
        local_1fc = local_3c8[0];
      }
    }
    else {
      FUN_1002c440(param_1,local_210 * (local_3d0 + -1) + 0x228,local_3c8,4,0);
    }
    FUN_10025120(param_1,local_210,local_2ec,local_3c8[0]);
    if (local_2e4 == 0) {
      local_2e4 = local_2ec;
      if (local_2ec != 0) {
        local_404[1] = 0;
        FUN_1002c440(param_1,local_210 * (local_2ec + -1) + 0x228,local_404 + 1,4,0);
      }
    }
    else if (local_2ec != 0) {
      local_404[0] = FUN_100254d0(param_1,local_210,local_2e4);
      FUN_1002c440(param_1,(local_404[0] + -1) * local_210 + 0x22c,&local_2ec,4,0);
      FUN_1002c440(param_1,local_210 * (local_2ec + -1) + 0x228,local_404,4,0);
    }
    local_2f0 = local_3d4;
    local_2ec = local_3d0;
    local_2e8 = local_3cc;
    FUN_1002c440(param_1,local_210 * (local_3c8[0] + -1) + 0x200,auStack_318,0xe4,0);
  }
  else {
    if (local_3d4 == 0) {
      if (local_3cc == 0) {
        local_200 = local_3d0;
      }
      else {
        FUN_1002c440(param_1,local_210 * (local_3cc + -1) + 0x234,&local_3d0,4,0);
      }
    }
    else {
      FUN_1002c440(param_1,local_210 * (local_3d4 + -1) + 0x22c,&local_3d0,4,0);
    }
    if (local_3d0 == 0) {
      if (local_3cc == 0) {
        local_1fc = local_3d4;
      }
    }
    else {
      FUN_1002c440(param_1,local_210 * (local_3d0 + -1) + 0x228,&local_3d4,4,0);
    }
  }
  FUN_1002c440(param_1,iVar5,local_408,iVar1,0);
  if (local_20c != 0) {
    FUN_10024150(param_1,local_210,auStack_1f4,local_20c,local_208 / local_210 + 1);
    local_20c = 0;
    local_208 = 0;
  }
  local_204 = local_40c;
  FUN_1002c440(param_1,0,&local_230,0x17c,0);
  FUN_10052c10(local_408);
  FUN_1002c2c0(param_1);
  return 1;
}

