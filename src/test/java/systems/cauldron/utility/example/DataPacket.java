package systems.cauldron.utility.example;

import lombok.Builder;
import lombok.Getter;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Consumer;

@Builder
@Getter
public class DataPacket {

    private boolean newFormat;
    private int type;
    private byte[] content;
    private boolean partial;

    public static DataPacket merge(DataPacket left, DataPacket right) {
        if (!left.partial) {
            throw new UnsupportedOperationException("cannot append onto non-partial DataPacket");
        }
        if (left.newFormat != right.newFormat) {
            throw new UnsupportedOperationException("cannot append DataPacket of different format");
        }
        if (left.type != right.type) {
            throw new UnsupportedOperationException("cannot append DataPacket of different type");
        }
        byte[] mergedContent = ByteBuffer.allocate(left.content.length + right.content.length)
                .put(left.content)
                .put(right.content)
                .array();
        return DataPacket.builder()
                .newFormat(left.newFormat)
                .type(left.type)
                .partial(right.partial)
                .content(mergedContent)
                .build();
    }

    @Override
    public String toString() {
        return "DataPacket{" +
                "newFormat=" + newFormat +
                ", type=" + type +
                ", content=" + Arrays.toString(content) +
                ", partial=" + partial +
                '}';
    }


    public static void readECDSAPublicKeyPacket(InputStream in) throws IOException {
        int version = in.read();
        long time = ((long) in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
        int algorithm = (byte) in.read();
        if (algorithm == 19) {
            byte[] oid = readBytesOfEncodedLength(in);
            BigInteger bigDecimal = readPoint(in);
        }
    }

    public static byte[] fingerprint(byte[] encodedPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest = MessageDigest.getInstance("SHA1", "BC");
        digest.update((byte) 0x99);
        digest.update((byte) (encodedPublicKey.length >> 8));
        digest.update((byte) encodedPublicKey.length);
        digest.update(encodedPublicKey);
        return digest.digest();
    }

    public static BigInteger readPoint(InputStream in) throws IOException {
        int length = (((in.read() << 8) | in.read()) + 7) / 8;
        byte[] bytes = in.readNBytes(length);
        return new BigInteger(1, bytes);
    }

    protected static byte[] readBytesOfEncodedLength(InputStream in) throws IOException {
        int length = in.read();
        byte[] buffer = new byte[length + 2];
        in.readNBytes(buffer, 2, length - 2);
        buffer[0] = (byte) 0x06;
        buffer[1] = (byte) length;
        return buffer;
    }

    public static void readPackets(InputStream in, Consumer<DataPacket> out) throws IOException {
        DataPacket previousPartial = null;
        while (true) {
            Optional<DataPacket> dataPacketResult = parsePacket(in);
            if (dataPacketResult.isEmpty()) {
                break;
            } else {
                DataPacket dataPacket = dataPacketResult.get();
                if (previousPartial != null) {
                    dataPacket = DataPacket.merge(previousPartial, dataPacket);
                    previousPartial = null;
                }
                if (dataPacket.isPartial()) {
                    previousPartial = dataPacket;
                } else {
                    out.accept(dataPacket);
                }
            }
        }
    }

    private static Optional<DataPacket> parsePacket(InputStream in) throws IOException {

        int typeHeader = in.read();
        if (typeHeader < 0) {
            return Optional.empty();
        }
        if ((typeHeader & 0x80) == 0) {
            throw new UnsupportedEncodingException("unexpected header value");
        }

        boolean isNewFormat = (typeHeader & 0x40) == 0;
        int type = typeHeader & 0x3f;

        int lengthHeaderStart = in.read();

        int length;
        boolean isPartial;
        if (lengthHeaderStart < 192) {
            isPartial = false;
            length = lengthHeaderStart;
        } else if (lengthHeaderStart <= 223) {
            isPartial = false;
            length = ((lengthHeaderStart - 192) << 8) + (in.read()) + 192;
        } else if (lengthHeaderStart == 255) {
            isPartial = false;
            length = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
        } else {
            isPartial = true;
            length = 1 << (lengthHeaderStart & 0x1f);
        }

        byte[] content = in.readNBytes(length);

        DataPacket dataPacket = DataPacket.builder()
                .newFormat(isNewFormat)
                .partial(isPartial)
                .type(type)
                .content(content)
                .build();
        return Optional.of(dataPacket);
    }
}
