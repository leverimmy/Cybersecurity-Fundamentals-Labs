package utils;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    
    // 生成 RSA 密钥对
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Constants.RSA);
        keyPairGenerator.initialize(Constants.RSA_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
    
    // 使用 RSA 公钥加密
    public static byte[] rsaEncrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(Constants.RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
    
    // 使用RSA私钥解密
    public static byte[] rsaDecrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(Constants.RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
    
    // 使用 AES 加密
    public static byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        SecretKey secretKey = getSecretKeyFromKey(key, Constants.AES, Constants.AES_KEY_SIZE);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        return cipher.doFinal(data);
    }
    
    // 使用 AES 解密
    public static byte[] aesDecrypt(byte[] encryptedData, byte[] key) throws Exception {
        SecretKey secretKey = getSecretKeyFromKey(key, Constants.AES, Constants.AES_KEY_SIZE);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        return cipher.doFinal(encryptedData);
    }
    
    // 使用 DES 加密
    public static byte[] desEncrypt(byte[] data, byte[] key) throws Exception {
        SecretKey secretKey = getSecretKeyFromKey(key, Constants.DES, Constants.DES_KEY_SIZE);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[8]));
        return cipher.doFinal(data);
    }
    
    // 使用 DES 解密
    public static byte[] desDecrypt(byte[] encryptedData, byte[] key) throws Exception {
        SecretKey secretKey = getSecretKeyFromKey(key, Constants.DES, Constants.DES_KEY_SIZE);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[8]));
        return cipher.doFinal(encryptedData);
    }
    
    // 从口令生成密钥
    private static SecretKey getSecretKeyFromKey(byte[] key, String algorithm, int keySize) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[16]; // 固定盐值简化实现
        KeySpec spec = new PBEKeySpec(new String(key).toCharArray(), salt, 65536, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, algorithm);
    }
    
    // 生成随机数
    public static byte[] generateRandomNumber(int bits) {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[bits / 8];
        random.nextBytes(randomBytes);
        return randomBytes;
    }
    
    // Base64 编码
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    
    // Base64 解码
    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }
    
    // 连接两个字节数组
    public static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
