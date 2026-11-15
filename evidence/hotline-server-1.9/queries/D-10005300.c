
uint FUN_10005000(undefined4 param_1,int param_2)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = 0;
    cVar2 = FUN_100053e0(param_2 + 8,2);
    if (cVar2 != '\0') {
      cVar2 = FUN_100053e0(param_2 + 8,0x27);
      if (cVar2 != '\0') {
        cVar2 = FUN_100053e0(param_2 + 8,1);
        if (cVar2 != '\0') {
          cVar2 = FUN_100053e0(param_2 + 8,0x26);
          if (cVar2 != '\0') {
            cVar2 = FUN_100053e0(param_2 + 8,0x19);
            if (cVar2 != '\0') {
              cVar2 = FUN_100053e0(param_2 + 8,0);
              if (cVar2 != '\0') {
                cVar2 = FUN_100053e0(param_2 + 8,3);
                if (cVar2 != '\0') {
                  cVar2 = FUN_100053e0(param_2 + 8,4);
                  if (cVar2 != '\0') {
                    cVar2 = FUN_100053e0(param_2 + 8,0x1c);
                    if (cVar2 != '\0') {
                      cVar2 = FUN_100053e0(param_2 + 8,5);
                      if (cVar2 != '\0') {
                        cVar2 = FUN_100053e0(param_2 + 8,6);
                        if (cVar2 != '\0') {
                          cVar2 = FUN_100053e0(param_2 + 8,7);
                          if (cVar2 != '\0') {
                            cVar2 = FUN_100053e0(param_2 + 8,8);
                            if (cVar2 != '\0') {
                              cVar2 = FUN_100053e0(param_2 + 8,0x1d);
                              if (cVar2 != '\0') {
                                cVar2 = FUN_100053e0(param_2 + 8,0x1e);
                                if (cVar2 != '\0') {
                                  cVar2 = FUN_100053e0(param_2 + 8,0x1f);
                                  if (cVar2 != '\0') {
                                    cVar2 = FUN_100053e0(param_2 + 8,0xe);
                                    if (cVar2 != '\0') {
                                      cVar2 = FUN_100053e0(param_2 + 8,0xf);
                                      if (cVar2 != '\0') {
                                        cVar2 = FUN_100053e0(param_2 + 8,0x10);
                                        if (cVar2 != '\0') {
                                          cVar2 = FUN_100053e0(param_2 + 8,0x11);
                                          if (cVar2 != '\0') {
                                            cVar2 = FUN_100053e0(param_2 + 8,0x18);
                                            if (cVar2 != '\0') {
                                              cVar2 = FUN_100053e0(param_2 + 8,0x16);
                                              if (cVar2 != '\0') {
                                                cVar2 = FUN_100053e0(param_2 + 8,0x17);
                                                if (cVar2 != '\0') {
                                                  cVar2 = FUN_100053e0(param_2 + 8,0x28);
                                                  if (cVar2 != '\0') {
                                                    cVar2 = FUN_100053e0(param_2 + 8,0x20);
                                                    if (cVar2 != '\0') {
                                                      cVar2 = FUN_100053e0(param_2 + 8,0x14);
                                                      if (cVar2 != '\0') {
                                                        cVar2 = FUN_100053e0(param_2 + 8,0x15);
                                                        if (cVar2 != '\0') {
                                                          cVar2 = FUN_100053e0(param_2 + 8,0x21);
                                                          if (cVar2 != '\0') {
                                                            cVar2 = FUN_100053e0(param_2 + 8,0x22);
                                                            if (cVar2 != '\0') {
                                                              cVar2 = FUN_100053e0(param_2 + 8,0x23)
                                                              ;
                                                              if (cVar2 != '\0') {
                                                                cVar2 = FUN_100053e0(param_2 + 8,
                                                                                     0x24);
                                                                if (cVar2 != '\0') {
                                                                  cVar2 = FUN_100053e0(param_2 + 8,
                                                                                       0x25);
                                                                  if (cVar2 != '\0') {
                                                                    cVar2 = FUN_100053e0(param_2 + 8
                                                                                         ,0xb);
                                                                    if (cVar2 != '\0') {
                                                                      cVar2 = FUN_100053e0(param_2 +
                                                                                           8,9);
                                                                      if (cVar2 != '\0') {
                                                                        cVar2 = FUN_100053e0(param_2
                                                                                             + 8,10)
                                                                        ;
                                                                        if ((cVar2 != '\0') &&
                                                                           (cVar2 = FUN_100053e0(
                                                  param_2 + 8,0x1a), cVar2 != '\0')) {
                                                    uVar1 = 1;
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
    uVar3 = *(byte *)(param_2 + 10) >> 1 & 1;
    uVar4 = 0;
    if ((*(int *)(param_2 + 8) == 0) && (*(int *)(param_2 + 0xc) == 0)) {
      uVar4 = 1;
    }
    uVar1 = (int)(-uVar4 | uVar4) >> 0x1f & 0x20U |
            (int)(-(uint)*(byte *)(param_2 + 0xb1) | (uint)*(byte *)(param_2 + 0xb1)) >> 0x1f & 8U |
            (int)(-(uint)*(byte *)(param_2 + 0xb0) | (uint)*(byte *)(param_2 + 0xb0)) >> 0x1f & 4U |
            -(*(byte *)(param_2 + 0x14a) >> 6 & 1) >> 0x1f | (int)(-uVar3 | uVar3) >> 0x1f & 2U |
            (int)(-uVar1 | uVar1) >> 0x1f & 0x10U;
  }
  return uVar1;
}

