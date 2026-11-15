
void FUN_10025120(undefined4 param_1,int param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack00000024;
  int local_50;
  undefined4 local_4c;
  int local_48;
  undefined4 local_44;
  int local_40;
  undefined4 local_3c;
  int local_38;
  undefined4 local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [5];
  
  if (param_3 != 0) {
    uStack00000024 = param_4;
    FUN_1002c440(param_1,(param_3 + -1) * param_2 + 0x230,&uStack00000024,4,0);
    iVar1 = FUN_1002c3b0(param_1,(param_3 + -1) * param_2 + 0x22c,&local_50,4,0);
    if (iVar1 != 4) {
      FUN_10027c30(1,9);
    }
    local_4c = uStack00000024;
    if (local_50 != 0) {
      FUN_1002c440(param_1,(local_50 + -1) * param_2 + 0x230,&local_4c,4,0);
      iVar1 = FUN_1002c3b0(param_1,(local_50 + -1) * param_2 + 0x22c,&local_48,4,0);
      if (iVar1 != 4) {
        FUN_10027c30(1,9);
      }
      local_44 = local_4c;
      if (local_48 != 0) {
        FUN_1002c440(param_1,(local_48 + -1) * param_2 + 0x230,&local_44,4,0);
        iVar1 = FUN_1002c3b0(param_1,(local_48 + -1) * param_2 + 0x22c,&local_40,4,0);
        if (iVar1 != 4) {
          FUN_10027c30(1,9);
        }
        local_3c = local_44;
        if (local_40 != 0) {
          FUN_1002c440(param_1,(local_40 + -1) * param_2 + 0x230,&local_3c,4,0);
          iVar1 = FUN_1002c3b0(param_1,(local_40 + -1) * param_2 + 0x22c,&local_38,4,0);
          if (iVar1 != 4) {
            FUN_10027c30(1,9);
          }
          local_34 = local_3c;
          if (local_38 != 0) {
            FUN_1002c440(param_1,(local_38 + -1) * param_2 + 0x230,&local_34,4,0);
            iVar1 = FUN_1002c3b0(param_1,(local_38 + -1) * param_2 + 0x22c,&local_30,4,0);
            if (iVar1 != 4) {
              FUN_10027c30(1,9);
            }
            local_2c = local_34;
            if (local_30 != 0) {
              FUN_1002c440(param_1,(local_30 + -1) * param_2 + 0x230,&local_2c,4,0);
              iVar1 = FUN_1002c3b0(param_1,(local_30 + -1) * param_2 + 0x22c,&local_28,4,0);
              if (iVar1 != 4) {
                FUN_10027c30(1,9);
              }
              local_24 = local_2c;
              iVar1 = FUN_100014b0(local_28);
              if (iVar1 != 0) {
                FUN_100254a0(param_1,(iVar1 + -1) * param_2 + 0x230,&local_24,4,0);
                iVar1 = FUN_100013a0(param_1,(iVar1 + -1) * param_2 + 0x22c,local_20,4,0);
                if (iVar1 != 4) {
                  FUN_10027c30(1,9);
                }
                uVar2 = FUN_100014b0(local_20[0]);
                FUN_10025120(param_1,param_2,uVar2,local_24);
              }
            }
          }
        }
      }
    }
  }
  return;
}

