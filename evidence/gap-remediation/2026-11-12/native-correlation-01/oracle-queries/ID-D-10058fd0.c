
void FUN_10058fd0(undefined4 *param_1,undefined4 param_2,uint param_3,undefined2 param_4,
                 undefined4 param_5,undefined4 param_6,int param_7,undefined4 param_8)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 auStack_110 [128];
  undefined1 local_50;
  byte local_4f;
  undefined2 local_4e;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  int local_40;
  undefined1 *local_24;
  
  uVar2 = *param_1;
  local_50 = 0;
  local_4f = (byte)(-(param_3 & 0xff) >> 0x1f);
  local_4e = param_4;
  local_4c = param_2;
  local_48 = param_5;
  local_44 = param_8;
  local_40 = param_7;
  if (param_7 == 0) {
    FUN_1006de90(uVar2,&local_50,0x14);
  }
  else {
    iVar1 = FUN_1006ddb0(param_7 + 0x14);
    local_24 = auStack_110 + 0x80;
    FUN_100539c0(iVar1,&local_50,0x14);
    FUN_100539c0(iVar1 + 0x14,param_6,param_7);
    FUN_1006de10(uVar2,iVar1);
  }
  return;
}

