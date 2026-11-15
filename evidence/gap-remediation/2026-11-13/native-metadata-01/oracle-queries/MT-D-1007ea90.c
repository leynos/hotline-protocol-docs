
void FUN_1007ea90(short *param_1,byte *param_2)

{
  short sVar1;
  short sVar2;
  char cVar3;
  undefined4 uVar4;
  undefined4 local_110;
  undefined1 auStack_10c [28];
  undefined1 auStack_f0 [18];
  short *local_de;
  byte *local_d0;
  uint local_cc;
  undefined4 local_c0;
  undefined1 auStack_88 [18];
  short *local_76;
  short local_72;
  
  uVar4 = *(undefined4 *)(param_1 + 1);
  sVar1 = *param_1;
  local_110 = 0x1c;
  sVar2 = FUN_1007ee80(param_1 + 3,(int)sVar1,auStack_10c,&local_110);
  if (sVar2 == 0) {
    cVar3 = FUN_1007ef20(auStack_10c);
    if (cVar3 == '\0') {
      sVar2 = -0x32;
    }
    else {
      local_76 = param_1 + 3;
      local_72 = sVar1;
      sVar2 = .glue::PBDTOpenInform(auStack_88);
      if (sVar2 == -0x32) {
        sVar2 = .glue::PBDTGetPath(auStack_88);
      }
    }
  }
  if (sVar2 == 0) {
    local_de = param_1 + 3;
    local_d0 = param_2 + 1;
    if (*param_2 < 0xc9) {
      local_cc = (uint)*param_2;
    }
    else {
      local_cc = 200;
    }
    local_c0 = uVar4;
    .glue::PBDTSetCommentSync(auStack_f0);
  }
  return;
}

