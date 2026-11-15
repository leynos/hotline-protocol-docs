
undefined4
FUN_1007ed00(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined1 *param_4)

{
  undefined4 uVar1;
  char cVar2;
  uint unaff_r27;
  undefined4 local_110;
  undefined1 auStack_10c [28];
  undefined1 auStack_f0 [18];
  undefined4 local_de;
  undefined1 *local_d0;
  undefined4 local_cc;
  undefined1 uStack_c5;
  undefined4 local_c0;
  undefined1 auStack_88 [18];
  undefined4 local_76;
  undefined2 local_72;
  uint local_6c;
  
  if (param_4 == (undefined1 *)0x0) {
    uVar1 = 0xffffffce;
  }
  else {
    *param_4 = 0;
    local_110 = 0x1c;
    uVar1 = FUN_1007ee80(param_3,param_1,auStack_10c,&local_110);
    if ((short)uVar1 == 0) {
      cVar2 = FUN_1007ef20(auStack_10c);
      if (cVar2 == '\0') {
        uVar1 = 0xffffffce;
      }
      else {
        local_72 = (undefined2)param_1;
        local_76 = param_3;
        uVar1 = .glue::PBDTOpenInform(auStack_88);
        unaff_r27 = local_6c & 1 ^ 1;
        if ((short)uVar1 == -0x32) {
          uVar1 = .glue::PBDTGetPath(auStack_88);
          unaff_r27 = 0;
        }
      }
    }
    if ((short)uVar1 == 0) {
      if ((unaff_r27 & 0xff) == 0) {
        local_d0 = param_4 + 1;
        local_cc = 0xff;
        local_de = param_3;
        local_c0 = param_2;
        uVar1 = .glue::PBDTGetCommentSync(auStack_f0);
        if ((short)uVar1 == 0) {
          *param_4 = uStack_c5;
        }
      }
    }
    else {
      uVar1 = FUN_1007eb90(param_1,param_2,param_3,param_4);
      if ((short)uVar1 != 0) {
        uVar1 = 0xffffec6c;
      }
    }
  }
  return uVar1;
}

