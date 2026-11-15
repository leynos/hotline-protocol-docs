
void FUN_10005d30(int param_1,char *param_2,int param_3)

{
  bool bVar1;
  short sVar3;
  undefined4 uVar2;
  undefined1 uVar4;
  ushort uVar5;
  undefined4 *puVar6;
  
  if ((param_2 != (char *)0x0) && (*param_2 != '\0')) {
    for (puVar6 = *(undefined4 **)(param_1 + 0x34); puVar6 != (undefined4 *)0x0;
        puVar6 = (undefined4 *)*puVar6) {
      sVar3 = FUN_1006d180((int)puVar6 + 0x79,*(undefined1 *)(puVar6 + 0x1e),param_2 + 1,*param_2);
      if (sVar3 == 0) {
        bVar1 = false;
        if ((puVar6[2] != *(int *)(param_3 + 4)) || (puVar6[3] != *(int *)(param_3 + 8))) {
          bVar1 = true;
        }
        if (bVar1) {
          *(undefined8 *)(puVar6 + 2) = *(undefined8 *)(param_3 + 4);
          uVar2 = FUN_10056380(0,0);
          FUN_100568b0(uVar2,0x6e,puVar6 + 2,8);
          FUN_10058ca0(puVar6[1],0x162,uVar2);
          FUN_100563d0(uVar2);
        }
        uVar5 = *(ushort *)(param_3 + 0x210);
        if (0x1f < uVar5) {
          uVar5 = 0x1f;
        }
        sVar3 = FUN_1006d180((int)puVar6 + 0x59,*(undefined1 *)(puVar6 + 0x16),param_3 + 0x212,uVar5
                            );
        if (sVar3 != 0) {
          uVar4 = FUN_100539c0((int)puVar6 + 0x59,param_3 + 0x212,uVar5);
          *(undefined1 *)(puVar6 + 0x16) = uVar4;
        }
        uVar5 = *(ushort *)(param_3 + 0x298);
        if (0x1f < uVar5) {
          uVar5 = 0x1f;
        }
        sVar3 = FUN_1006d180((int)puVar6 + 0x79,*(undefined1 *)(puVar6 + 0x1e),param_3 + 0x29a,uVar5
                            );
        if (sVar3 != 0) {
          uVar4 = FUN_100539c0((int)puVar6 + 0x79,param_3 + 0x29a,uVar5);
          *(undefined1 *)(puVar6 + 0x1e) = uVar4;
        }
        if ((*(byte *)((int)puVar6 + 0xb) >> 5 & 1) == 0) {
          uVar5 = *(ushort *)(param_3 + 0x210);
          if (0x1f < uVar5) {
            uVar5 = 0x1f;
          }
          sVar3 = FUN_1006d180((int)puVar6 + 0x39,*(undefined1 *)(puVar6 + 0xe),param_3 + 0x212,
                               uVar5);
          if (sVar3 != 0) {
            bVar1 = true;
            uVar4 = FUN_100539c0((int)puVar6 + 0x39,param_3 + 0x212,uVar5);
            *(undefined1 *)(puVar6 + 0xe) = uVar4;
          }
        }
        else {
          sVar3 = FUN_1006d180((int)puVar6 + 0x39,*(undefined1 *)(puVar6 + 0xe),(int)puVar6 + 0x19,
                               *(undefined1 *)(puVar6 + 6));
          if (sVar3 != 0) {
            bVar1 = true;
            FUN_100539c0(puVar6 + 0xe,puVar6 + 6,*(byte *)(puVar6 + 6) + 1);
          }
        }
        if (bVar1) {
          FUN_10004f30(param_1,puVar6);
        }
      }
    }
  }
  return;
}

