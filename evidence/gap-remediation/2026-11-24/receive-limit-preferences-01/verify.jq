def result($id): map(select(.query.id == $id)) | if length == 1 then .[0].result.structuredContent else null end;
def at($address): .items[] | select(.address == $address) | .instruction;
length == 7 and
all(.[]; .program.name == "HLserver19.pef" and .program.function_count == 1840 and
  .program.language_id == "PowerPC:BE:32:default" and
  .program.sha256 == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b" and
  .result.isError == false) and
(result("preferences-callers") | .total == 1 and .has_more == false and
  .items[0].from == "10000b9c") and
(result("call-window") |
  at("10000b94") == "addi r4,r31,0xd8" and at("10000b98") == "addi r5,r31,0x44" and
  at("10000b9c") == "bl 0x10008fd0" and at("10000ba8") == "bl 0x1000a460") and
(result("preferences-input-name").hex == "05 50 72 65 66 73") and
(result("following-input-name") | .hex | startswith("06 42 61 6e 6e 65 64 ")) and
(result("post-preferences").code | contains("FUN_1000a070(param_1,&local_20)")) and
(result("following-helper").code | contains("FUN_1002af80(0xfffffffe,0,0x100902ed,0,0)"))
