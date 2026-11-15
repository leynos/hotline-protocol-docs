
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_10027ea0(int param_1)

{
  undefined **ppuVar1;
  undefined *puVar2;
  char cVar3;
  undefined1 auStack_300 [128];
  undefined **local_26c;
  undefined1 auStack_240 [4];
  undefined4 local_23c;
  undefined1 auStack_238 [28];
  undefined1 *local_21c;
  undefined1 local_218;
  undefined1 auStack_217 [255];
  byte local_118 [268];
  
  local_21c = auStack_300 + 0x80;
  if ((*(byte *)(param_1 + 0x10) >> 6 & 1) == 0) {
    ppuVar1 = &_toc;
    if (_DAT_100893e4 == 0) {
      puVar2 = (undefined *).glue::GetNewDialog(0x24dd,0,0xffffffff);
      local_26c[-0x1ccf] = puVar2;
      ppuVar1 = local_26c;
      if (puVar2 == (undefined *)0x0) {
        FUN_10001bd0(s_UError___couldn_t_create_error_d_1009394c);
        .glue::SysBeep(0x14);
        .glue::SysBeep(0x14);
        .glue::ExitToShell();
      }
    }
    local_218 = FUN_10027d40(param_1,auStack_217,0xff);
    cVar3 = FUN_10027930(param_1,local_118 + 2,0xfd);
    local_118[0] = cVar3 + 2;
    local_118[1] = 0x28;
    local_118[local_118[0]] = 0x29;
    cVar3 = FUN_10053980(0x400);
    if (cVar3 == '\0') {
      FUN_10001bd0(s_An_unknown_error_has_occured__No_1009397b + 0x46);
      .glue::SysBeep(0x14);
    }
    else {
      .glue::GetDialogItem(ppuVar1[-0x1ccf],2,auStack_240,&local_23c,auStack_238);
      .glue::SetDialogItemText(local_23c,&local_218);
      .glue::GetDialogItem(local_26c[-0x1ccf],4,auStack_240,&local_23c,auStack_238);
      .glue::SetDialogItemText(local_23c,local_118);
      .glue::GetDialogWindow(local_26c[-0x1ccf]);
      .glue::SelectWindow();
      .glue::GetDialogWindow(local_26c[-0x1ccf]);
      .glue::ShowWindow();
      .glue::ModalDialog(0,auStack_240);
      .glue::GetDialogWindow(local_26c[-0x1ccf]);
      .glue::HideWindow();
      cVar3 = FUN_1002a0d0();
      *(bool *)(local_26c + 0x1797) = cVar3 == '\0';
      *(undefined1 *)((int)local_26c + 0x63d5) = 1;
    }
  }
  return;
}

