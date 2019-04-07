package pckg;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;


public class Client {
    private Certificate sharedClientCertificate;
    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private BigInteger dhPrivateKey;
    private BigInteger dhSharedKey;

    //diffie helmen key signed by rsa public key
    private byte[] signedDHSharedKey;
    private SessionKeys keys;
    private StreamManager manager;

    private Socket clientSocket;

    /**
     * Constructor
     *
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     */
    public Client() throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        sharedClientCertificate = DiffieHellman.getCertificate("CASignedClientCertificate.pem");
        rsaPrivateKey = DiffieHellman.getRSAPrivateKey("clientPrivateKey.der");
        rsaPublicKey = sharedClientCertificate.getPublicKey();
        dhPrivateKey = new BigInteger(MessageUtils.getRandLong() + "");
        dhSharedKey = DiffieHellman.getDHSharedKey(dhPrivateKey);
        signedDHSharedKey = DiffieHellman.signKey(rsaPrivateKey, dhSharedKey);

        clientSocket = new Socket("127.0.0.1", MessageUtils.PORT_NUM);
        clientSocket.setKeepAlive(true);

        manager = new StreamManager(clientSocket);
        initHandShake();
    }

    /**
     * Performs TLS handshake
     *
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     */
    private void initHandShake() throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, IllegalBlockSizeException, BadPaddingException {
        //generate the nonce
        byte[] nonce = generateNonce();
        manager.writeAndStore(nonce);
        System.out.println("Nonce sent");

        //get the certificate and (signed) shared keys
        ArrayList<Object> serverCredentials = manager.readInputStream();
        for (Object o : serverCredentials) {
            manager.writeToHistory(o);
        }
        System.out.println("Received server keys");

        //verify the RSA public key
        //use RSA public key to verify the signed shared key
        if (!DiffieHellman.verifyCertificate((Certificate) serverCredentials.get(0)) || !DiffieHellman.verifySignature((Certificate) serverCredentials.get(0), (BigInteger) serverCredentials.get(1), (byte[]) serverCredentials.get(2))) {
            manager.errorClose(clientSocket, "Unable to verify certificate/signature");
            return;
        }
        System.out.println("Server checks out");

        //send client's keys
        manager.writeAndStore(sharedClientCertificate, dhSharedKey, signedDHSharedKey);
        System.out.println("Client keys sent");

        //get the shared secret from the shared key
        BigInteger sharedSecretKey = DiffieHellman.getDHSharedSecret((BigInteger) serverCredentials.get(1), dhPrivateKey);

        //generate the 6 session keys
        keys = new SessionKeys(nonce, sharedSecretKey);


        byte[] serverMacHash = (byte[]) manager.readInputStream().get(0);
        byte[] checkMacHash = keys.getServerMac().doFinal(manager.getMsgHistory());

        //check server's mac hash
        if (!Arrays.equals(serverMacHash, checkMacHash)) {
            manager.errorClose(clientSocket, "Server mac hash does not match");
            return;
        }
        System.out.println("Server's mac checks out");

        //send client's final message hashed with client's mac
        manager.writeToHistory(serverMacHash);
        byte[] hashMsg = keys.getClientMac().doFinal(manager.getMsgHistory());

        manager.writeAndStore(hashMsg);
        System.out.println("Client mac hash sent");

        //get the file info from the server
        byte[] encrypted = (byte[]) manager.readInputStream().get(0);
        byte[] decrypted = MessageUtils.decryptMsg(encrypted, keys.getServerEncrypt(), keys.getServerIV());
        if(!MessageUtils.verifyEncryption(keys.getServerEncrypt(), keys.getServerIV(), keys.getServerMac(), decrypted, MessageUtils.LONG_BYTES)) {
            manager.errorClose(clientSocket, "File info corrupted");
            return;
        }

        //gets the file length
        long fileLen = MessageUtils.byteArrayToLong(decrypted);

        //calculate how many segments you're expecting
        int fileSegmentCount = ((int) Math.ceil(fileLen / (double) MessageUtils.FILE_SIZE));
        //calculates the length of the last file segment
        int tailLen = ((int) (fileLen % MessageUtils.FILE_SIZE));
        System.out.println("Received fileSegmentCount: " + fileSegmentCount + "\nTail segment length: " + tailLen);

        for(int i = 0; i < fileSegmentCount - 1; ++i) {
            //encrypted msg segment from the server
            encrypted = (byte[]) manager.readInputStream().get(0);
            decrypted = MessageUtils.decryptMsg(encrypted, keys.getServerEncrypt(), keys.getServerIV());

            if(!MessageUtils.verifyEncryption(keys.getServerEncrypt(), keys.getServerIV(), keys.getServerMac(), decrypted, MessageUtils.FILE_SIZE)) {
                manager.errorClose(clientSocket, "File corrupted or missing");
                return;
            }
        }

        encrypted = (byte[]) manager.readInputStream().get(0);
        decrypted = MessageUtils.decryptMsg(encrypted, keys.getServerEncrypt(), keys.getServerIV());
        if(!MessageUtils.verifyEncryption(keys.getServerEncrypt(), keys.getServerIV(), keys.getServerMac(), decrypted, tailLen)) {
            manager.errorClose(clientSocket, "File corrupted or missing");
            return;
        }

        manager.writeToStream(MessageUtils.getEncryptedMsg(keys.getClientEncrypt(), keys.getClientIV(), keys.getClientMac(), MessageUtils.FILE_CONFIRM_MSG.getBytes()));
    }

    /**
     * generates 32 byte nonce
     *
     * @return
     */
    public byte[] generateNonce() {
        SecureRandom sr = new SecureRandom();
        byte[] nonce = new byte[32];
        sr.nextBytes(nonce);

        return nonce;
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        try {
            Thread.sleep(3000);
        } catch (Exception e) {

        }

        for(int i = 0; i < 25; ++i) {
            Client c = new Client();
        }
        Client c = new Client();
    }
}
