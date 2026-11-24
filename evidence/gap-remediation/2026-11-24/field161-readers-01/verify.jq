def record($id): map(select(.query.id == $id)) | if length == 1 then .[0].result.structuredContent else null end;
def insn($addr; $instruction): .items | any(.address == $addr and .instruction == $instruction);
length == 5 and
all(.[]; .program.name == "HLserver19.pef" and .program.language_id == "PowerPC:BE:32:default" and
  .program.function_count == 1840 and .program.sha256 == $scan[0].input_sha256 and .result.isError == false) and
$scan[0].input_sha256 == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b" and
$scan[0].section_bytes == 558872 and
$scan[0].candidates == [{"address":"10011c3c","opcode":32,"base_register":29,"displacement":1052,"read_width":4}] and
(record("field161-load") | insn("10011c3c"; "lwz r5,0x41c(r29)") and insn("10011c44"; "li r4,0xa1") and insn("10011c48"; "bl 0x10056a90")) and
(record("field161-width").code | contains("param_3 & 0xffff0000") and contains("local_10,2)") and contains("local_c,4)")) and
(record("constructor-refs") | .total == 1 and .has_more == false and .items[0].from == "100000c8") and
(record("login-builder-refs") | .total == 1 and .has_more == false and .items[0].from == "1000b568") and
(record("constructor-caller").code | contains("FUN_10000160(iVar1)") and contains("_DAT_10096074 = iVar1") and contains("FUN_100007b0(iVar1)"))
