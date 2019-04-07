package pckg;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Stores the keys for a current TLS session
 */
public class SessionKeys {
    private SecretKeySpec serverEncrypt, clientEncrypt;
    private Mac serverMac, clientMac;
    private IvParameterSpec serverIV, clientIV;

    /**
     * Generates 6 session keys used for a handshake session
     *
     * @param clientNonce
     * @param sharedDHSecret
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    SessionKeys(byte[] clientNonce, BigInteger sharedDHSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(clientNonce, "HmacSHA256"));

        byte[] prk = mac.doFinal(sharedDHSecret.toByteArray());
        byte[] serverEncrypt = hkdfExpand(prk, "server encrypt");
        byte[] clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt");
        byte[] serverMac = hkdfExpand(clientEncrypt, "server MAC");
        byte[] clientMac = hkdfExpand(serverMac, "client MAC");
        byte[] serverIV = hkdfExpand(clientMac, "server IV");
        byte[] clientIV = hkdfExpand(serverIV, "client IV");

        this.serverEncrypt = new SecretKeySpec(serverEncrypt, "AES");
        this.clientEncrypt = new SecretKeySpec(clientEncrypt, "AES");

        this.serverMac = Mac.getInstance("HmacSHA256");
        this.serverMac.init(new SecretKeySpec(serverMac, "HmacSHA256"));

        this.clientMac = Mac.getInstance("HmacSHA256");
        this.clientMac.init(new SecretKeySpec(clientMac, "HmacSHA256"));

        this.serverIV = new IvParameterSpec(serverIV);
        this.clientIV = new IvParameterSpec(clientIV);
    }

    /**
     * Expands a given key a tag string
     *
     * @param inputKey
     * @param tag
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static byte[] hkdfExpand(byte[] inputKey, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(inputKey, "HmacSHA256"));
        byte[] newTag = Arrays.copyOf(tag.getBytes(), tag.length() + 1);
        newTag[newTag.length - 1] = 1;
        return Arrays.copyOf(mac.doFinal(tag.getBytes()), 16);
    }

    public SecretKeySpec getServerEncrypt() {
        return serverEncrypt;
    }

    public SecretKeySpec getClientEncrypt() {
        return clientEncrypt;
    }

    public Mac getServerMac() {
        return serverMac;
    }

    public Mac getClientMac() {
        return clientMac;
    }

    public IvParameterSpec getServerIV() {
        return serverIV;
    }

    public IvParameterSpec getClientIV() {
        return clientIV;
    }
}
