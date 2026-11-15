
undefined4 FUN_1006cd80(int param_1,int param_2,int param_3)

{
  bool bVar1;
  char *pcVar2;
  char *pcVar3;
  
  pcVar2 = (char *)(param_1 + -1);
  pcVar3 = (char *)(param_2 + -1);
  do {
    bVar1 = param_3 == 0;
    param_3 = param_3 + -1;
    if (bVar1) {
      return 1;
    }
    pcVar2 = pcVar2 + 1;
    pcVar3 = pcVar3 + 1;
  } while (*pcVar2 == *pcVar3);
  return 0;
}

