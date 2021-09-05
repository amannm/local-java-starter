package systems.cauldron.utility.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRing;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class Application {

    private final static Logger LOG = LogManager.getLogger(Application.class);

    public static void main(String[] args) {
        printNameAndFingerprint(args[0].getBytes(StandardCharsets.UTF_8));
    }

    public static void printNameAndFingerprint(byte[] pemBytes) {
        try (InputStream decoderStream = new ArmoredInputStream(new ByteArrayInputStream(pemBytes))) {
            PGPPublicKeyRing publicKeyRing = new BcPGPPublicKeyRing(decoderStream);
            PGPPublicKey publicKey = publicKeyRing.getPublicKey();
            String name = publicKey.getUserIDs().next();
            String fingerprint = Hex.toHexString(publicKey.getFingerprint()).toUpperCase(Locale.ROOT);
            System.out.println(name);
            System.out.println(fingerprint);
        } catch (Exception ex) {
            LOG.error("failed to print name and fingerprint", ex);
        }
    }
}