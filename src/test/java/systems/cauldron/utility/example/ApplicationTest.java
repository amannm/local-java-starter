package systems.cauldron.utility.example;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class ApplicationTest {

    public static final String PUBLIC_KEY_PEM = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mFIEYTKqkhMIKoZIzj0DAQcCAwTABz6T9GBMItQAGyRfCtptYVlWK+nlITznMtfF\n" +
            "28tn/GfkH2tSL7NG2hZyYzkzLBbw95YQhpDLycr3bOLVrxFotCNTaGFydG8gU2hh\n" +
            "cnQgPHNoYXJ0QGNsb3ducGVuaXMub3JnPoiQBBMTCAA4FiEEfZ5faA3wn2s050JV\n" +
            "XCeuOT/dSWgFAmEyqpICGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQXCeu\n" +
            "OT/dSWhidgEA0L7bebI0uYqATc2UbbHVU+ZKqDjoAKtJjvk3CyEe+SkA/0naQtOp\n" +
            "SVd4whZeyGX4Jzf6j9mrxZmSLP9s2M1Vbg+N\n" +
            "=Mdv2\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void ensureEntryPointWorks() {
        assertDoesNotThrow(() -> Application.main(new String[]{PUBLIC_KEY_PEM}));
    }

    @Test
    public void ensureLibraryApproachWorks() {
        try {
            byte[] pgpPublicKeyPem = PUBLIC_KEY_PEM.getBytes(StandardCharsets.UTF_8);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pgpPublicKeyPem);
            InputStream decoderStream = new ArmoredInputStream(byteArrayInputStream);
            PGPPublicKeyRing pgpPublicKeys = new PGPPublicKeyRing(decoderStream, new BcKeyFingerprintCalculator());
            PGPPublicKey publicKey = pgpPublicKeys.getPublicKey();
            String name = publicKey.getUserIDs().next();
            String fingerprint = Hex.toHexString(publicKey.getFingerprint()).toUpperCase(Locale.ROOT);
            assertNotNull(name);
            assertNotNull(fingerprint);
        } catch (Exception ex) {
            fail(ex);
        }
    }

    @Disabled
    @Test
    public void ensureHandrolledApproachWorks() {
        try {
            byte[] pgpPublicKeyPem = PUBLIC_KEY_PEM.getBytes(StandardCharsets.UTF_8);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pgpPublicKeyPem);
            InputStream decoderStream = new ArmoredInputStream(byteArrayInputStream);
            DataPacket.readPackets(decoderStream, packet -> {
                System.out.println(packet.toString());
            });
        } catch (Exception ex) {
            fail(ex);
        }
    }
}