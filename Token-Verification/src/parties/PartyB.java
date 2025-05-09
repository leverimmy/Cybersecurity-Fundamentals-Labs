package parties;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import utils.Constants;
import utils.Crypto;

public class PartyB {
    private final byte[] password;
    private final ServerSocket serverSocket;
    
    public PartyB(String password, int port) throws IOException {
        this.password = password.getBytes(Constants.CHARSET);
        this.serverSocket = new ServerSocket(port);
    }
    
    public void runProtocol() throws Exception {
        System.out.println("Party B: Waiting for connection...");
        try (Socket socket = serverSocket.accept();
             DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            
            System.out.println("Party B: Connection established with A");
            
            // 步骤 1: 接收加密的公钥并解密
            String encryptedPublicKeyStr = in.readUTF();
            byte[] decryptedPublicKey = Crypto.aesDecrypt(Crypto.base64Decode(encryptedPublicKeyStr), password);
            PublicKey publicKey = KeyFactory.getInstance(Constants.RSA)
                    .generatePublic(new X509EncodedKeySpec(decryptedPublicKey));
            System.out.println("Party B: Received and decrypted A's public key");
            
            // 步骤 2: 生成会话密钥 Ks 并双重加密发送给 A
            byte[] Ks = Crypto.generateRandomNumber(Constants.AES_KEY_SIZE);
            byte[] encryptedWithRSA = Crypto.rsaEncrypt(Ks, publicKey);
            byte[] encryptedWithAES = Crypto.aesEncrypt(encryptedWithRSA, password);
            out.writeUTF(Crypto.base64Encode(encryptedWithAES));
            System.out.println("Party B: Sent double encrypted session key to A");
            
            // 步骤 3: 接收加密的 NA 并解密
            String encryptedNAStr = in.readUTF();
            byte[] NA = Crypto.desDecrypt(Crypto.base64Decode(encryptedNAStr), Ks);
            System.out.println("Party B: Received and decrypted NA from A");
            
            // 步骤 4: 生成 NB，拼接 NA||NB 并加密发送给 A
            byte[] NB = Crypto.generateRandomNumber(Constants.RANDOM_NUMBER_SIZE);
            byte[] NANB = Crypto.concatenate(NA, NB);
            byte[] encryptedNANB = Crypto.desEncrypt(NANB, Ks);
            out.writeUTF(Crypto.base64Encode(encryptedNANB));
            System.out.println("Party B: Sent encrypted NA||NB to A");
            
            // 步骤 6: 接收加密的 NB 并验证
            String encryptedNBStr = in.readUTF();
            byte[] receivedNB = Crypto.desDecrypt(Crypto.base64Decode(encryptedNBStr), Ks);
            
            if (!MessageDigest.isEqual(NB, receivedNB)) {
                throw new SecurityException("Party B: NB verification failed");
            }
            System.out.println("Party B: Verified NB, authentication of A successful");
            
            System.out.println("Party B: Protocol completed successfully. Session established.");
        }
    }
    
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: PartyB <password> <port>");
            return;
        }
        
        try {
            PartyB partyB = new PartyB(args[0], Integer.parseInt(args[1]));
            partyB.runProtocol();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("Verification failed. Please check the password and try again.");
        }
    }
}
