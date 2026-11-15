
void FUN_100055a0(undefined4 param_1,undefined4 param_2,char param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar2;
  undefined1 auStack_330 [128];
  undefined4 local_270;
  int local_26c;
  undefined4 local_268;
  undefined4 local_264;
  uint local_260;
  undefined1 *local_244;
  byte local_240;
  undefined1 auStack_23f [255];
  int local_140;
  undefined4 local_13c;
  undefined4 local_138;
  undefined4 local_134;
  undefined2 local_130;
  ushort local_12e;
  undefined1 auStack_12c [280];
  
  FUN_10056820(param_4);
  local_270 = 0;
  uVar1 = FUN_1002cb20(param_2,0);
  local_244 = auStack_330 + 0x80;
LAB_10005678:
  do {
    cVar2 = FUN_1002ce00(uVar1,&local_270,&local_240,&local_26c,&local_268,&local_264,0,0);
    if (cVar2 == '\0') {
      FUN_10052e90(uVar1);
      return;
    }
  } while ((local_260 & 1) != 0);
  if (param_3 != '\0') goto code_r0x10005608;
  goto LAB_10005618;
code_r0x10005608:
  if (local_26c == 0x48546674) {
LAB_10005618:
    local_134 = 0;
    local_130 = 0;
    local_12e = (ushort)local_240;
    FUN_100539c0(auStack_12c,auStack_23f,local_240);
    local_140 = local_26c;
    local_13c = local_268;
    local_138 = local_264;
    FUN_100568b0(param_4,200,&local_140,local_240 + 0x14);
  }
  goto LAB_10005678;
}

