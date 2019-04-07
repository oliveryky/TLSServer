package pckg;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;

/**
 * Helper functions for handshake
 */
public class MessageUtils {
    //default port number
    public static final int PORT_NUM = 8080;

    //file segment size
    public static final int FILE_SIZE = 1024;

    public static final int LONG_BYTES = Long.BYTES;

    public static final String FILE_CONFIRM_MSG = "File Received";
    public static final String FILE_FAILED_MSG = "File not received or corrupted";

    private static Random rand = new Random();

    /**
     * encrypts the msg concatenated with its mac version
     * @param key
     * @param iv
     * @param mac
     * @param msg
     * @return
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    public static byte[] getEncryptedMsg(SecretKeySpec key, IvParameterSpec iv, Mac mac, byte[] msg) throws BadPaddingException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] macMsg = mac.doFinal(msg);
        byte[] toEncrypt = joinByteArray(msg, macMsg);
        return encryptMsg(key, iv, toEncrypt);
    }

    /**
     * concatentates two arrays
     * @param lhs
     * @param rhs
     * @return
     */
    public static byte[] joinByteArray(byte[] lhs, byte[] rhs) {
        byte[] ret = Arrays.copyOf(lhs, lhs.length + rhs.length);
        System.arraycopy(rhs, 0, ret, lhs.length, rhs.length);

        return ret;
    }

    /**
     * encrypts a msg
     * @param key
     * @param iv
     * @param toEncrypt
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private static byte[] encryptMsg(SecretKeySpec key, IvParameterSpec iv, byte[] toEncrypt) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(toEncrypt);
    }

    /**
     * decrypts the msg and verifies its mac using the other party's key from your end
     * @param key
     * @param iv
     * @param mac
     * @param decrypted
     * @param splitIdx
     * @return
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    public static boolean verifyEncryption(SecretKeySpec key, IvParameterSpec iv, Mac mac, byte[] decrypted, int splitIdx) throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
//        byte[] decrypted = decryptMsg(encrypted, key, iv);
        byte[] msg = Arrays.copyOfRange(decrypted, 0, splitIdx);
        byte[] macHash = Arrays.copyOfRange(decrypted, splitIdx, decrypted.length);

        return Arrays.equals(mac.doFinal(msg), macHash);
    }

    /**
     * decrypts a msg
     * @param encrypted
     * @param key
     * @param iv
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] decryptMsg(byte[] encrypted, SecretKeySpec key, IvParameterSpec iv) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return cipher.doFinal(encrypted);
    }

    /**
     * Converts long to byte array
     * @param val
     * @return
     */
    public static byte[] longToByteArray(long val) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(MessageUtils.LONG_BYTES);
        byteBuffer.putLong(val);

        return byteBuffer.array();
    }

    /**
     * Converts byte array to long
     * @param arr
     * @return
     */
    public static long byteArrayToLong(byte[] arr) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(MessageUtils.LONG_BYTES);
        byteBuffer.put(arr, 0, MessageUtils.LONG_BYTES);
        byteBuffer.flip();

        return byteBuffer.getLong();
    }

    /**
     * @return random long
     */
    public static long getRandLong() {
        return rand.nextLong();
    }
}
