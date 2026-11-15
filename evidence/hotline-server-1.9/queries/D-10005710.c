
void FUN_10005710(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4)

{
  undefined1 *puVar1;
  undefined4 uVar2;
  char cVar3;
  uint uVar4;
  undefined1 auStack_490 [128];
  undefined1 local_3d0 [4];
  undefined4 local_3cc;
  int local_3c8;
  uint local_3c4;
  undefined4 local_3c0;
  undefined1 *local_3a4;
  undefined1 *local_38c;
  undefined1 local_388;
  undefined1 auStack_387 [255];
  undefined2 local_288;
  undefined2 local_286;
  byte local_284;
  undefined1 auStack_283 [15];
  undefined4 local_274;
  undefined4 local_270;
  byte local_26c;
  undefined1 auStack_26b [271];
  undefined1 auStack_15c [20];
  undefined4 local_148;
  undefined4 local_144;
  
  puVar1 = auStack_490 + 0x80;
  FUN_10056820(param_3);
  local_3cc = 0;
  uVar2 = FUN_1002cb20(param_2,0);
  local_3a4 = puVar1;
  if (param_4 < 0xf) {
    while (cVar3 = FUN_1002ce00(uVar2,&local_3cc,&local_288,&local_3c8,0,0,0,0), cVar3 != '\0') {
      if ((local_3c4 & 1) == 0) {
        uVar4 = (uint)local_288._0_1_;
        if (local_3c8 == 0x666c6472) {
          local_288 = CONCAT11(1,(undefined1)local_288);
        }
        else if (local_3c8 == 0x484c4e5a) {
          local_288 = CONCAT11(10,(undefined1)local_288);
        }
        else {
          local_288 = CONCAT11(0xff,(undefined1)local_288);
        }
        FUN_100568b0(param_3,0x140,&local_288,uVar4 + 1);
      }
    }
  }
  else {
    while (cVar3 = FUN_1002ce00(uVar2,&local_3cc,&local_388,&local_3c8,0,local_3d0,0,0),
          cVar3 != '\0') {
      if ((local_3c4 & 1) == 0) {
        if (local_3c8 == 0x666c6472) {
          local_288 = 2;
          local_286 = local_3d0._2_2_;
          local_284 = FUN_100539c0(auStack_283,auStack_387,local_388);
          FUN_100568b0(param_3,0x143,&local_288,local_284 + 6);
        }
        else if (local_3c8 == 0x484c4e5a) {
          local_38c = puVar1;
          local_3c0 = FUN_1002af80(param_2,0,&local_388,0,0);
          FUN_10022830(local_3c0,auStack_15c);
          local_288 = 3;
          local_286 = auStack_15c._18_2_;
          FUN_1006f350(auStack_15c,&local_284);
          local_274 = local_148;
          local_270 = local_144;
          local_26c = FUN_100539c0(auStack_26b,auStack_387,local_388);
          FUN_100568b0(param_3,0x143,&local_288,local_26c + 0x20);
          FUN_1002b2f0(local_3c0);
        }
      }
    }
  }
  FUN_10052e90(uVar2);
  return;
}

