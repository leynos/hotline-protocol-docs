
undefined4 FUN_10003bd0(undefined4 param_1,char *param_2,char param_3,int *param_4,int *param_5)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined1 local_b0;
  undefined1 auStack_af [135];
  
  *param_5 = 0;
  if (*param_4 != 0) {
    FUN_10052e90(*param_4);
    *param_4 = 0;
  }
  if ((param_2 == (char *)0x0) || (*param_2 == '\0')) {
    uVar1 = 0;
  }
  else {
    iVar2 = FUN_1002af80(0xfffffffe,0,param_2,0x20a,0);
    if (iVar2 == 0) {
      FUN_10006860(param_1,0x1008fc38,param_2);
      uVar1 = 0;
    }
    else {
      iVar3 = FUN_1002c8a0(iVar2);
      *param_5 = iVar3;
      uVar5 = 0xffff;
      if (iVar3 != 0x54455854) {
        uVar5 = 0x3fffc;
      }
      FUN_1002c220(iVar2,0x21);
      uVar4 = FUN_1002c4d0(iVar2,0);
      if (uVar5 < uVar4) {
        local_b0 = FUN_10054180(auStack_af,0x7f,s_<__s>_is_larger_that__lu_bytes_a_1008fc57,param_2,
                                uVar5);
        FUN_10051090(0x1008fc97,&local_b0,0x3e9,0x84,0);
        if (iVar2 != 0) {
          FUN_1002b2f0(iVar2);
        }
        uVar1 = 0;
      }
      else {
        iVar3 = FUN_10052c50(uVar4,0);
        *param_4 = iVar3;
        uVar1 = FUN_10053290();
        FUN_1002c3b0(iVar2,0,uVar1,uVar4,0);
        FUN_10053310(iVar3);
        if (*param_5 == 0x54455854) {
          FUN_1006cf70(*param_4,0,0x1008fc52,2,0x1008fc55,1);
        }
        if (param_3 == '\0') {
          FUN_10006860(param_1,0x1008fccf,param_2);
        }
        else {
          FUN_10006860(param_1,0x1008fcbb,param_2);
        }
        if (iVar2 != 0) {
          FUN_1002b2f0(iVar2);
        }
        uVar1 = 1;
      }
    }
  }
  return uVar1;
}

