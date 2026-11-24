
void FUN_1000a460(int param_1)

{
  bool bVar1;
  uint uVar2;
  char *pcVar3;
  uint uVar4;
  int local_20;
  uint local_1c;
  
  FUN_10055460(&local_20);
  FUN_1000a070(param_1,&local_20);
  uVar2 = local_1c;
  for (uVar4 = 1; uVar4 <= uVar2; uVar4 = uVar4 + 1) {
    bVar1 = false;
    if (uVar4 != 0) {
      if (uVar4 <= local_1c) {
        bVar1 = true;
      }
    }
    if (bVar1) {
      pcVar3 = *(char **)(local_20 + uVar4 * 4 + -4);
    }
    else {
      pcVar3 = (char *)0x0;
    }
    if (*pcVar3 == '\0') {
      FUN_1006d290(pcVar3);
    }
    else {
      FUN_100554e0(param_1 + 0x448);
    }
  }
  FUN_10055880(&local_20);
  FUN_10055480(&local_20,0);
  return;
}

