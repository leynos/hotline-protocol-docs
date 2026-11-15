
undefined4 FUN_1002f800(undefined2 *param_1,uint param_2,short *param_3)

{
  short local_60 [2];
  undefined2 local_5c;
  undefined4 local_5a;
  undefined8 local_56;
  undefined8 local_4e;
  undefined8 local_46;
  undefined8 local_3e;
  undefined8 local_36;
  undefined8 local_2e;
  undefined8 local_26;
  undefined8 local_1e;
  
  if ((param_2 != 0) || (param_3 != (short *)0x0)) {
    FUN_1002f600(param_1,&local_5c,local_60);
    if ((param_2 & 0x200) != 0) {
      *param_1 = local_5c;
      *(undefined4 *)(param_1 + 1) = local_5a;
      *(undefined8 *)(param_1 + 3) = local_56;
      *(undefined8 *)(param_1 + 7) = local_4e;
      *(undefined8 *)(param_1 + 0xb) = local_46;
      *(undefined8 *)(param_1 + 0xf) = local_3e;
      *(undefined8 *)(param_1 + 0x13) = local_36;
      *(undefined8 *)(param_1 + 0x17) = local_2e;
      *(undefined8 *)(param_1 + 0x1b) = local_26;
      *(undefined8 *)(param_1 + 0x1f) = local_1e;
      if (local_60[0] == 4) {
        local_60[0] = 2;
      }
      else if (local_60[0] == 5) {
        local_60[0] = 3;
      }
      else if (local_60[0] == 6) {
        if (param_3 != (short *)0x0) {
          *param_3 = 6;
        }
        if ((param_2 & 2) != 0) {
          return 1;
        }
        FUN_10027c30(4,0x80);
      }
    }
    if (param_3 != (short *)0x0) {
      *param_3 = local_60[0];
    }
    if (local_60[0] == 0) {
      if ((param_2 & 1) != 0) {
        return 1;
      }
    }
    else if (local_60[0] != 1) {
      if ((param_2 & 4) != 0) {
        return 1;
      }
      if ((param_2 & 0x40) != 0) {
        FUN_10027c30(4,0x73);
      }
      if ((param_2 & 8) != 0) {
        if (local_60[0] == 2) {
          return 0;
        }
        return 1;
      }
      if ((param_2 & 0x80) != 0) {
        if (local_60[0] == 2) {
          return 0;
        }
        FUN_10027c30(4,0x7c);
        return 0;
      }
      if ((param_2 & 0x10) != 0) {
        if (local_60[0] == 3) {
          return 0;
        }
        return 1;
      }
      if ((param_2 & 0x100) == 0) {
        return 0;
      }
      if (local_60[0] == 3) {
        return 0;
      }
      FUN_10027c30(4,0x7d);
      return 0;
    }
    if ((param_2 & 2) != 0) {
      return 1;
    }
    if ((param_2 & 0x20) != 0) {
      if ((param_2 & 0x88) == 0) {
        if ((param_2 & 0x110) == 0) {
          FUN_10027c30(4,0x66);
        }
        else {
          FUN_10027c30(4,0x68);
        }
      }
      else {
        FUN_10027c30(4,0x67);
      }
    }
  }
  return 0;
}

