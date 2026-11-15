
void FUN_1002e120(undefined2 *param_1)

{
  undefined4 uVar1;
  undefined1 auStack_50 [18];
  undefined2 *local_3e;
  undefined2 local_3a;
  undefined2 local_38;
  undefined2 local_34;
  undefined2 local_1c;
  undefined4 local_16;
  
  if (param_1[0x28] != 0) {
    local_3e = param_1 + 3;
    local_3a = 0;
    local_38 = param_1[0x28];
    local_34 = 0;
    uVar1 = .glue::PBGetFCBInfoSync(auStack_50);
    if ((short)uVar1 != 0) {
      FUN_10028190(uVar1,0,0);
    }
    *param_1 = local_1c;
    *(undefined4 *)(param_1 + 1) = local_16;
  }
  return;
}

