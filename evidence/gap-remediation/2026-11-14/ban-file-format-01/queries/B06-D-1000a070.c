
void FUN_1000a070(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  char cVar7;
  int iVar2;
  int iVar3;
  undefined1 *puVar4;
  int iVar5;
  uint uVar6;
  undefined1 auStack_110 [128];
  ushort local_50 [2];
  int local_4c;
  int local_48;
  int local_44 [6];
  undefined1 *local_2c;
  
  iVar1 = FUN_1002af80(0xfffffffe,0,0x100902ed,0,0);
  local_4c = iVar1;
  cVar7 = FUN_1002b750(iVar1,0);
  if (cVar7 == '\0') {
    if (local_4c != 0) {
      FUN_1002b2f0(local_4c);
    }
  }
  else {
    local_48 = iVar1;
    FUN_1002c220(iVar1,0x21);
    local_2c = auStack_110 + 0x80;
    iVar2 = FUN_1002c3b0(iVar1,0,local_50,2,0);
    if (local_50[0] < 3) {
      local_44[0] = 0;
      iVar3 = FUN_1002c3b0(iVar1,iVar2,local_44,4,0);
      iVar2 = iVar2 + iVar3;
      if (local_44[0] == 0) {
        FUN_1002b880(iVar1);
        FUN_1002c2c0(local_48);
        if (local_4c != 0) {
          FUN_1002b2f0(local_4c);
        }
      }
      else {
        while (local_44[0] != 0) {
          local_44[0] = local_44[0] + -1;
          puVar4 = (undefined1 *)FUN_1006d260(0x74);
          if (puVar4 != (undefined1 *)0x0) {
            *(undefined4 *)(puVar4 + 0xc) = 0;
            *(undefined4 *)(puVar4 + 8) = 0;
            *(undefined4 *)(puVar4 + 4) = 0xffffffff;
            *puVar4 = 1;
            puVar4[0x10] = 0;
            puVar4[0x31] = 0;
          }
          iVar3 = FUN_1002c3b0(iVar1,iVar2,puVar4,1,0);
          iVar5 = FUN_1002c3b0(iVar1,iVar2 + iVar3,puVar4 + 8,4,0);
          iVar5 = iVar2 + iVar3 + iVar5;
          if (local_50[0] == 1) {
            *(undefined4 *)(puVar4 + 0xc) = *(undefined4 *)(puVar4 + 8);
          }
          else {
            iVar2 = FUN_1002c3b0(iVar1,iVar5,puVar4 + 0xc,4,0);
            iVar5 = iVar5 + iVar2;
          }
          iVar2 = FUN_1002c3b0(iVar1,iVar5,puVar4 + 0x10,0x21,0);
          iVar5 = iVar5 + iVar2;
          if (local_50[0] == 1) {
            local_50[1] = 0;
            iVar2 = FUN_1002c3b0(iVar1,iVar5,local_50 + 1,2,0);
            iVar5 = iVar5 + iVar2;
          }
          iVar2 = FUN_1002c3b0(iVar1,iVar5,puVar4 + 0x31,1,0);
          if (iVar2 != 1) {
            FUN_1006d290(puVar4);
            FUN_1002c2c0(local_48);
            if (local_4c == 0) {
              return;
            }
            FUN_1002b2f0(local_4c);
            return;
          }
          if (0x3f < (byte)puVar4[0x31]) {
            FUN_1006d290(puVar4);
            FUN_1002c2c0(local_48);
            if (local_4c == 0) {
              return;
            }
            FUN_1002b2f0(local_4c);
            return;
          }
          uVar6 = FUN_1002c3b0(iVar1,iVar5 + 1,puVar4 + 0x32,puVar4[0x31],0);
          if ((byte)puVar4[0x31] != uVar6) {
            FUN_1006d290(puVar4);
            FUN_1002c2c0(local_48);
            if (local_4c == 0) {
              return;
            }
            FUN_1002b2f0(local_4c);
            return;
          }
          iVar2 = iVar5 + 1 + (uint)(byte)puVar4[0x31];
          FUN_100554e0(param_2,puVar4);
        }
        local_44[0] = local_44[0] + -1;
        FUN_1002c2c0(local_48);
        if (local_4c != 0) {
          FUN_1002b2f0(local_4c);
        }
      }
    }
    else {
      FUN_1002c2c0(local_48);
      if (local_4c != 0) {
        FUN_1002b2f0(local_4c);
      }
    }
  }
  return;
}

