
undefined2 *
FUN_1002af80(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            )

{
  char cVar2;
  undefined2 *puVar1;
  undefined2 local_68;
  undefined4 local_66;
  undefined8 local_62;
  undefined8 local_5a;
  undefined8 local_52;
  undefined8 local_4a;
  undefined8 local_42;
  undefined8 local_3a;
  undefined8 local_32;
  undefined8 local_2a;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_1002e8b0(param_1,param_2,0,0,param_3,&local_68);
  cVar2 = FUN_1002f800(&local_68,param_4,param_5);
  if (cVar2 == '\0') {
    puVar1 = (undefined2 *)FUN_10052b70(0x54);
    *puVar1 = local_68;
    *(undefined4 *)(puVar1 + 1) = local_66;
    *(undefined8 *)(puVar1 + 3) = local_62;
    *(undefined8 *)(puVar1 + 7) = local_5a;
    *(undefined8 *)(puVar1 + 0xb) = local_52;
    *(undefined8 *)(puVar1 + 0xf) = local_4a;
    *(undefined8 *)(puVar1 + 0x13) = local_42;
    *(undefined8 *)(puVar1 + 0x17) = local_3a;
    *(undefined8 *)(puVar1 + 0x1b) = local_32;
    *(undefined8 *)(puVar1 + 0x1f) = local_2a;
  }
  else {
    puVar1 = (undefined2 *)0x0;
  }
  return puVar1;
}

