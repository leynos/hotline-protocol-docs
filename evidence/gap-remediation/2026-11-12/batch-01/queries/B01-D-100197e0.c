
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_100197e0(int param_1,undefined1 *param_2)

{
  int iVar1;
  undefined1 *puVar2;
  undefined1 uVar4;
  short sVar3;
  char cVar5;
  uint uVar6;
  int iVar7;
  undefined1 auStack_500 [128];
  undefined4 local_440;
  int local_43c;
  uint local_438;
  undefined1 *local_41c;
  undefined1 *local_404;
  undefined1 auStack_400 [256];
  undefined1 auStack_300 [4];
  undefined8 local_2fc;
  ushort local_68;
  undefined1 auStack_66 [70];
  
  iVar1 = FUN_10007160(_DAT_10096074);
  if (iVar1 != 0) {
    iVar7 = 0;
    local_440 = 0;
    local_41c = auStack_500 + 0x80;
    while( true ) {
      cVar5 = FUN_1002ce00(iVar1,&local_440,auStack_400,&local_43c,0,0,0,0);
      if (cVar5 == '\0') break;
      if ((local_43c == 0x666c6472) && ((local_438 & 1) == 0)) {
        local_404 = auStack_500 + 0x80;
        FUN_100073c0(_DAT_10096074,auStack_400,auStack_300);
        uVar6 = (uint)local_68;
        puVar2 = (undefined1 *)FUN_10052b70(uVar6 + 10);
        *(undefined8 *)(puVar2 + 1) = local_2fc;
        uVar4 = FUN_100539c0(puVar2 + 10,auStack_66,uVar6);
        puVar2[9] = uVar4;
        if (param_2 == (undefined1 *)0x0) {
LAB_100198e8:
          if (((byte)puVar2[3] >> 1 & 1) == 0) {
            if (((byte)puVar2[2] >> 1 & 1) == 0) {
              if ((puVar2[2] & 1) == 0) {
                if (-1 < (char)puVar2[3]) {
                  if (((byte)puVar2[3] >> 6 & 1) == 0) {
                    if ((-1 < (char)puVar2[4]) && ((puVar2[3] & 1) == 0)) goto LAB_10019950;
                  }
                }
              }
            }
            *puVar2 = 3;
          }
          else {
            *puVar2 = 2;
          }
        }
        else {
          sVar3 = FUN_10053a60(puVar2 + 10,puVar2[9],param_2 + 1,*param_2,0);
          if (sVar3 != 0) goto LAB_100198e8;
          *puVar2 = 1;
        }
LAB_10019950:
        FUN_100554e0(param_1 + 0x70,puVar2);
        iVar7 = iVar7 + 1;
      }
    }
    FUN_10052e90(iVar1);
    if (iVar7 != 0) {
      FUN_10055910(param_1 + 0x70,PTR_PTR_10088db4,0);
      FUN_10082630(param_1,1,iVar7);
      FUN_10019e90(param_1);
    }
  }
  return;
}

