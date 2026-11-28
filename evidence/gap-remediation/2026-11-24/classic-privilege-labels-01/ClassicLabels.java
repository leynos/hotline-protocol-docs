import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pef.ContainerHeader;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

class ClassicLabels {
    public static void main(String[] args) throws Exception {
        byte[] file = Files.readAllBytes(Path.of(args[0]));
        var digest = MessageDigest.getInstance("SHA-256");
        String sha = HexFormat.of().formatHex(digest.digest(file));
        if (!sha.equals("7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315")) {
            throw new IllegalArgumentException("Unexpected Classic client identity");
        }
        var header = new ContainerHeader(new ByteArrayProvider(file));
        header.parse();
        var section = header.getSections().get(1);
        byte[] data = section.getUnpackedData(TaskMonitor.DUMMY);
        if (data.length != 0x246e9 || section.getContainerOffset() != 0x1399d0) {
            throw new IllegalStateException("Unexpected section geometry");
        }
        System.out.printf("input %s%nsection sha256 %s%n", sha, HexFormat.of().formatHex(digest.digest(data)));
        for (String label : new String[]{"CMyAdminEditUserWin", "Can Send Messages", "Can Disconnect Users"}) {
            byte[] term = label.getBytes(StandardCharsets.US_ASCII);
            for (int i = 1; i <= data.length - term.length; i++) {
                if (Arrays.equals(data, i, i + term.length, term, 0, term.length)) {
                    System.out.printf("%s text=%08x previous-byte=%02x length=%d%n", label,
                        0x10135810 + i, Byte.toUnsignedInt(data[i - 1]), term.length);
                }
            }
        }
    }
}
