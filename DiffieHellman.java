package pckg;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class DiffieHellman {
    //DH_BASE for diffie helman
    private static final BigInteger DH_BASE = new BigInteger("2");

    //DH_PRIME for diffie helman
    private static final BigInteger DH_PRIME = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    /**
     * Generates a Certificate from an input file
     *
     * @param fileName
     * @return
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    public static Certificate getCertificate(String fileName) throws CertificateException, FileNotFoundException {
        InputStream certInputStream = new FileInputStream(fileName);
        return CertificateFactory.getInstance("X.509").generateCertificate(certInputStream);
    }

    /**
     * Generates a rsa private key from a signed certificate
     *
     * @param fileName
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getRSAPrivateKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * Generates diffie helman shared key
     *
     * @param dhPrivateKey
     * @return
     */
    public static BigInteger getDHSharedKey(BigInteger dhPrivateKey) {
        return DH_BASE.modPow(dhPrivateKey, DH_PRIME);
    }

    /**
     * Derives the shared secret from diffie helman exchange
     *
     * @param dhSharedKey
     * @param dhPrivateKey
     * @return
     */
    public static BigInteger getDHSharedSecret(BigInteger dhSharedKey, BigInteger dhPrivateKey) {
        return dhSharedKey.modPow(dhPrivateKey, DH_PRIME);
    }

    /**
     * Signs the shared diffie helman public key with the end user's private rsa key
     *
     * @param rsaPrivateKey
     * @param dhSharedKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] signKey(PrivateKey rsaPrivateKey, BigInteger dhSharedKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(rsaPrivateKey);
        sig.update(dhSharedKey.toByteArray());
        return sig.sign();
    }

    /**
     * Verifies the shared certificate with a Certificate Authority's
     *
     * @param sharedCertificate
     * @return
     */
    public static boolean verifyCertificate(Certificate sharedCertificate) {
        try {
            Certificate caCertificate = getCertificate("CAcertificate.pem");
            sharedCertificate.verify(caCertificate.getPublicKey());
            return true;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Verifies the signed diffie helman key
     *
     * @param sharedCertificate
     * @param dhSharedKey
     * @param signedKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifySignature(Certificate sharedCertificate, BigInteger dhSharedKey, byte[] signedKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initVerify(sharedCertificate.getPublicKey());
        sig.update(dhSharedKey.toByteArray());
        return sig.verify(signedKey);
    }

}
