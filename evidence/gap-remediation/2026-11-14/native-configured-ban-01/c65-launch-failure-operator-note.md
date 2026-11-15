# C65 launch failure retained as failure

This note transcribes the observed tool output; no original terminal stream was saved as a file.

`python scripts/mac_runtime.py display --display :114 state/mac-runtime/native-configured-apply-01` raised `FileExistsError` because `display` requires a new directory and the image runtime already existed. The next shell command attempted `sheep --service --isolate-network`; its managed unit exited status 1 before the emulator opened the disk or guest capture. C65 `sheep-journal.log` and terminal receipts record the failed unit and no guest PCAP. Host primary capture contains only its 24-byte header. C66 used the distinct new display path `state/mac-displays/native-configured-apply-c66` and preserved C65's stopped `isolated-network` metadata under `isolated-network-c65-stopped`.

This was an operator path error, not a native-server protocol observation. No C65 UI edit or frontend connection occurred.
