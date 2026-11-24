($stat | split("\n")) as $lines
| ($application | split("\n") | map(split("\t") | last)) as $names
| ($loader[0].result.content[0].text | fromjson | .code) as $code
| .bytes == 119 and .format_word == 5
  and .sha256 == "e375ab2877f2fb572f01d8b4fc5759e3e14bae845a6f78dc9e2afdc21e50c568"
  and .passes_outer_loader_guard == (.bytes > 95 and (.format_word == 4 or .format_word == 5))
  and ($code | contains("(0x5f < uVar4)") and contains("local_2020 == 4 || (local_2020 == 5)"))
  and ($lines | index("File Path: /Hotline19/Prefs") != null and index("Allocated") != null
       and index("Catalog Record: 11198") != null and index("Size:\t119") != null
       and index("Resource fork size:\t0") != null)
  and ($application | contains("-/r 11198:\tPrefs\n"))
  and ($names | index("Banned") == null)
  and ($staged | split("\n") | index("Prefs") == null)
