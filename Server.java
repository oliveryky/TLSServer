package pckg;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

public class Server {
    private Certificate sharedServerCertificate;
    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private BigInteger dhPrivateKey;
    private BigInteger dhSharedKey;

    //diffie helmen key signed by rsa public key
    private byte[] signedDHSharedKey;

    private ServerSocketChannel listener;

    /**
     * Constructor
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws SignatureException
     */
    public Server() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {
        sharedServerCertificate = DiffieHellman.getCertificate("CASignedServerCertificate.pem");
        rsaPrivateKey = DiffieHellman.getRSAPrivateKey("serverPrivateKey.der");
        rsaPublicKey = sharedServerCertificate.getPublicKey();
        dhPrivateKey = new BigInteger(MessageUtils.getRandLong() + "");
        dhSharedKey = DiffieHellman.getDHSharedKey(dhPrivateKey);
        signedDHSharedKey = DiffieHellman.signKey(rsaPrivateKey, dhSharedKey);
        listener = ServerSocketChannel.open();
        listener.bind(new InetSocketAddress(MessageUtils.PORT_NUM));
        listener.configureBlocking(true);
        System.out.println("Server started");
        initServer();
    }

    /**
     * Starts the server listening to local host port 8080
     * @throws IOException
     */
    private void initServer() throws IOException {
        while (true) {
            SocketChannel client = listener.accept();

            //Handle each TLS request on a new thread
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        System.out.println("Connected");

                        StreamManager manager = new StreamManager(client.socket());

                        //get the nonce from the client
                        byte[] nonce = (byte[]) manager.readInputStream().get(0);
                        manager.writeToHistory(nonce);
                        System.out.println("Nonce received");

                        //send server's key/certificates
                        manager.writeAndStore(sharedServerCertificate, dhSharedKey, signedDHSharedKey);
                        System.out.println("Server keys sent");

                        //get the certificate and (signed) shared keys
                        ArrayList<Object> clientStuff = manager.readInputStream();
                        for(Object o: clientStuff) {
                            manager.writeToHistory(o);
                        }
                        System.out.println("Received client keys");

                        //verify the RSA public key
                        //use RSA public key to verify the signed shared key
                        if(!DiffieHellman.verifyCertificate((Certificate) clientStuff.get(0)) || !DiffieHellman.verifySignature((Certificate) clientStuff.get(0), (BigInteger) clientStuff.get(1), (byte[]) clientStuff.get(2))){
                            manager.errorClose(client.socket(), "Unable to verify certificate/signature");
                            client.close();
                            return;
                        }
                        System.out.println("Client checks out");

                        //get the shared secret from the shared key
                        BigInteger sharedSecretKey = DiffieHellman.getDHSharedSecret((BigInteger) clientStuff.get(1), dhPrivateKey);

                        //generate the 6 session keys
                        SessionKeys keys = new SessionKeys(nonce, sharedSecretKey);

                        //use mac to hash all messages so far and send it to the client
                        byte[] hashMsg = keys.getServerMac().doFinal(manager.getMsgHistory());
                        manager.writeAndStore(hashMsg);
                        System.out.println("Server mac hash sent");

                        //receives client's final message hashed with client's mac and verify it
                        byte[] clientMacHash = (byte[]) manager.readInputStream().get(0);
                        manager.writeToHistory(clientMacHash);
                        byte[] checkMacHash = keys.getClientMac().doFinal(manager.getMsgHistory());

                        if(!Arrays.equals(checkMacHash, checkMacHash)) {
                            manager.errorClose(client.socket(), "Server mac hash does not match");
                            client.close();
                            return;
                        }
                        System.out.println("Client's mac checks out\nTLS handshake finished");

                        byte[] fileArr = new byte[MessageUtils.FILE_SIZE];
                        File file = new File("test.txt");
                        //send the file length to the client
                        byte[] fileLen = MessageUtils.longToByteArray(file.length());

                        manager.writeToStream(MessageUtils.getEncryptedMsg(keys.getServerEncrypt(), keys.getServerIV(), keys.getServerMac(), fileLen));
                        System.out.println("Packet count sent");

                        try(InputStream fileInputStream = new FileInputStream(file)) {
                            int bytesRead = 0;
                            while((bytesRead = fileInputStream.read(fileArr)) > 0) {
                                byte[] msg = Arrays.copyOf(fileArr, bytesRead);

                                manager.writeToStream(MessageUtils.getEncryptedMsg(keys.getServerEncrypt(), keys.getServerIV(), keys.getServerMac(), msg));
                            }

                            byte[] encrypted = (byte[]) manager.readInputStream().get(0);
                            byte[] decrypted = MessageUtils.decryptMsg(encrypted, keys.getClientEncrypt(), keys.getClientIV());
                            if(!MessageUtils.verifyEncryption(keys.getClientEncrypt(), keys.getClientIV(), keys.getClientMac(), decrypted, MessageUtils.FILE_CONFIRM_MSG.length())) {
                                manager.errorClose(client.socket(), "Client failed to receive bytes");
                                System.out.println(MessageUtils.FILE_FAILED_MSG);
                                client.close();
                                return;
                            }

                            System.out.println(MessageUtils.FILE_CONFIRM_MSG);
                        }
                    }catch(Exception e){
                        e.printStackTrace();
                        try {
                            client.close();
                        } catch (IOException e1) {
                            e1.printStackTrace();
                        }
                    }
                }
            }).start();
        }
    }

    public static void main(String[] args) {
        try {
            Server server = new Server();
        }catch(Exception e) {
            e.printStackTrace();
        }
    }
}
