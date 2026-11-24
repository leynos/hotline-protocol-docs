def parsed_labels:
  $locations | split("\n") | map(select(startswith("Can ")) |
    capture("^(?<label>.+) text=(?<address>[0-9a-f]{8}) previous-byte=(?<prefix>[0-9a-f]{2}) length=(?<length>[0-9]+)$"));
($segment[0].result.structuredContent.items | any(
  .name == "PackedData" and .initialized == true and .start == $manifest[0].initialized_start and
  .end == $manifest[0].initialized_end and .size == $manifest[0].unpacked_size)) and
($anchor[0].result.structuredContent | .address == "1014fef8" and (.ascii | startswith("CMyAdminEditUserWin"))) and
($locations | split("\n") | .[0:3] == [
  "input " + $manifest[0].client_data_sha256,
  "section sha256 " + $manifest[0].unpacked_sha256,
  "CMyAdminEditUserWin text=1014fef8 previous-byte=00 length=19"]) and
(parsed_labels | length == 4 and
  all(.[]; (.label | utf8bytelength) == (.length | tonumber) and
    ((.label == "Can Send Messages" and .prefix == "11") or (.label == "Can Disconnect Users" and .prefix == "14"))) and
  map([.label,.address]) == ($offsets[0] | map([.label,.loaded_text_address]))) and
($offsets[0] | map([.packed_text_offset,.loaded_text_address,.loaded_length_address]) == [
  ["14d33c","1014c725","1014c724"],["14f9b4","1014fdb1","1014fdb0"],
  ["14d306","1014c6ef","1014c6ee"],["14f97e","1014fd7b","1014fd7a"]])
