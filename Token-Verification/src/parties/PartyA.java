package parties;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import utils.Constants;
import utils.Crypto;

public class PartyA {
    private final byte[] password;
    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    
    public PartyA(String password, String host, int port) throws IOException {
        this.password = password.getBytes(Constants.CHARSET);
        this.socket = new Socket(host, port);
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
    }
    
    public void runProtocol() throws Exception {
        System.out.println("Party A: Starting protocol...");
        
        // 步骤 1: 生成 RSA 密钥对并用 AES 加密公钥发送给 B
        KeyPair keyPair = Crypto.generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        byte[] encryptedPublicKey = Crypto.aesEncrypt(publicKey.getEncoded(), password);
        out.writeUTF(Crypto.base64Encode(encryptedPublicKey));
        System.out.println("Party A: Sent encrypted public key to B");
        
        // 步骤 2: 接收双重加密的会话密钥
        String encryptedKsMessage = in.readUTF();
        byte[] decryptedWithAES = Crypto.aesDecrypt(Crypto.base64Decode(encryptedKsMessage), password);
        byte[] sessionKeyBytes = Crypto.rsaDecrypt(decryptedWithAES, privateKey);
        System.out.println("Party A: Received and decrypted session key");
        
        // 步骤 3: 生成随机数 NA 并用 DES 加密发送给 B
        byte[] NA = Crypto.generateRandomNumber(Constants.RANDOM_NUMBER_SIZE);
        byte[] encryptedNA = Crypto.desEncrypt(NA, sessionKeyBytes);
        out.writeUTF(Crypto.base64Encode(encryptedNA));
        System.out.println("Party A: Sent encrypted NA to B");
        
        // 步骤 4: 接收 NA||NB 并验证
        String encryptedNANB = in.readUTF();
        byte[] decryptedNANB = Crypto.desDecrypt(Crypto.base64Decode(encryptedNANB), sessionKeyBytes);
        
        // 拆分 NA 和 NB
        byte[] receivedNA = new byte[NA.length];
        byte[] NB = new byte[decryptedNANB.length - NA.length];
        System.arraycopy(decryptedNANB, 0, receivedNA, 0, NA.length);
        System.arraycopy(decryptedNANB, NA.length, NB, 0, NB.length);
        
        // 验证 NA
        if (!MessageDigest.isEqual(NA, receivedNA)) {
            throw new SecurityException("Party A: NA verification failed");
        }
        System.out.println("Party A: Verified NA, authentication of B successful");
        
        // 步骤 5: 加密 NB 并发送回 B
        byte[] encryptedNB = Crypto.desEncrypt(NB, sessionKeyBytes);
        out.writeUTF(Crypto.base64Encode(encryptedNB));
        System.out.println("Party A: Sent encrypted NB back to B");
        
        System.out.println("Party A: Protocol completed successfully. Session established.");
        
        // 关闭连接
        in.close();
        out.close();
        socket.close();
    }
    
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: PartyA <password> <host> <port>");
            return;
        }
        
        try {
            PartyA partyA = new PartyA(args[0], args[1], Integer.parseInt(args[2]));
            partyA.runProtocol();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("Verification failed. Please check the password and try again.");
        }
    }
}
