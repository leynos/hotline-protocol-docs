
int FUN_100254d0(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20 [5];
  
  if (param_3 == 0) {
    param_3 = 0;
  }
  else {
    iVar1 = FUN_1002c3b0(param_1,(param_3 + -1) * param_2 + 0x22c,&local_40,4,0);
    if (iVar1 != 4) {
      FUN_10027c30(1,9);
    }
    if (local_40 != 0) {
      if (local_40 == 0) {
        param_3 = 0;
      }
      else {
        iVar1 = FUN_1002c3b0(param_1,(local_40 + -1) * param_2 + 0x22c,&local_3c,4,0);
        if (iVar1 != 4) {
          FUN_10027c30(1,9);
        }
        param_3 = local_40;
        if (local_3c != 0) {
          if (local_3c == 0) {
            param_3 = 0;
          }
          else {
            iVar1 = FUN_1002c3b0(param_1,(local_3c + -1) * param_2 + 0x22c,&local_38,4,0);
            if (iVar1 != 4) {
              FUN_10027c30(1,9);
            }
            param_3 = local_3c;
            if (local_38 != 0) {
              if (local_38 == 0) {
                param_3 = 0;
              }
              else {
                iVar1 = FUN_1002c3b0(param_1,(local_38 + -1) * param_2 + 0x22c,&local_34,4,0);
                if (iVar1 != 4) {
                  FUN_10027c30(1,9);
                }
                param_3 = local_38;
                if (local_34 != 0) {
                  if (local_34 == 0) {
                    param_3 = 0;
                  }
                  else {
                    iVar1 = FUN_1002c3b0(param_1,(local_34 + -1) * param_2 + 0x22c,&local_30,4,0);
                    if (iVar1 != 4) {
                      FUN_10027c30(1,9);
                    }
                    param_3 = local_34;
                    if (local_30 != 0) {
                      if (local_30 == 0) {
                        param_3 = 0;
                      }
                      else {
                        iVar1 = FUN_1002c3b0(param_1,(local_30 + -1) * param_2 + 0x22c,&local_2c,4,0
                                            );
                        if (iVar1 != 4) {
                          FUN_10027c30(1,9);
                        }
                        param_3 = local_30;
                        if (local_2c != 0) {
                          if (local_2c == 0) {
                            param_3 = 0;
                          }
                          else {
                            iVar1 = FUN_1002c3b0(param_1,(local_2c + -1) * param_2 + 0x22c,&local_28
                                                 ,4,0);
                            if (iVar1 != 4) {
                              FUN_10027c30(1,9);
                            }
                            param_3 = local_2c;
                            if (local_28 != 0) {
                              if (local_28 == 0) {
                                param_3 = 0;
                              }
                              else {
                                iVar1 = FUN_1002c3b0(param_1,(local_28 + -1) * param_2 + 0x22c,
                                                     &local_24,4,0);
                                if (iVar1 != 4) {
                                  FUN_10027c30(1,9);
                                }
                                param_3 = local_28;
                                if (local_24 != 0) {
                                  if (local_24 == 0) {
                                    param_3 = 0;
                                  }
                                  else {
                                    iVar1 = FUN_100013a0(param_1,(local_24 + -1) * param_2 + 0x22c,
                                                         local_20,4,0);
                                    if (iVar1 != 4) {
                                      FUN_10027c30(1,9);
                                    }
                                    param_3 = local_24;
                                    if (local_20[0] != 0) {
                                      uVar2 = FUN_100014b0(local_20[0]);
                                      param_3 = FUN_100254d0(param_1,param_2,uVar2);
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return param_3;
}

