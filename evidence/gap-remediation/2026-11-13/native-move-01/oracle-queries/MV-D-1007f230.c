
undefined4 FUN_1007f230(undefined2 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined1 auStack_70 [18];
  int local_5e;
  undefined2 local_5a;
  undefined2 local_54;
  undefined4 local_40;
  
  if (param_3 == 0) {
    uVar1 = 0xffffffce;
  }
  else {
    local_54 = 0xffff;
    local_5e = param_3;
    local_5a = param_1;
    local_40 = param_2;
    uVar1 = .glue::PBGetCatInfoSync(auStack_70);
  }
  return uVar1;
}

