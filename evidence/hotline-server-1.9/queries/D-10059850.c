
undefined4 FUN_10059850(int param_1,int *param_2)

{
  bool bVar1;
  undefined4 uVar2;
  undefined1 auStack_110 [128];
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined1 *local_2c;
  
  local_2c = auStack_110 + 0x80;
  bVar1 = false;
  if (*(int *)(param_1 + 8) == *param_2) {
    if (*(int *)(param_1 + 0xc) == param_2[1]) {
      if (*(int *)(param_1 + 0x10) == param_2[2]) {
        if (*(int *)(param_1 + 0x14) == param_2[3]) goto LAB_100598b4;
      }
    }
  }
  bVar1 = true;
LAB_100598b4:
  if (bVar1) {
    local_50 = *(undefined4 *)(param_1 + 8);
    local_4c = *(undefined4 *)(param_1 + 0xc);
    local_48 = *(undefined4 *)(param_1 + 0x10);
    local_44 = *(undefined4 *)(param_1 + 0x14);
    FUN_100345f0(&local_50,param_2);
    *(int *)(param_1 + 8) = *param_2;
    *(int *)(param_1 + 0xc) = param_2[1];
    *(int *)(param_1 + 0x10) = param_2[2];
    *(int *)(param_1 + 0x14) = param_2[3];
    FUN_10082630(param_1,&local_50);
    if (*(int *)(param_1 + 4) != 0) {
      FUN_10082630(*(undefined4 *)(param_1 + 4),param_1,param_2);
    }
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

