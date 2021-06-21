import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class Main {
    public static byte[] S;
    public static byte[] iv1Glob;


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException {
        initialPart("383F8C3FED2160F863AE303799FA99C738BA60D88BB26BAC672584D39584CA13E13D48365FE025A37E73D67527B4A6AE44EEB302D3A92BE991F8C7B42CD07D3926365291C7BA7FA59F2F5B5034167B1984AEB866A48F997D46819581A10B62E69806FF988DC69A6694ACE451FE687EEAF43F96678836C39F77577938E15449CE");
        byte[] password = Arrays.copyOfRange(S,0,16);

        finalPart("BF141DC52E3AA3D6ED1E2508E7BE1176A8C6C447C8AB3F2B389FC932352ECF0CE13A9C75AFBB5A81320723B70F69D01457E50BA107CEB7146B016382BD75D39FD38C88FD386F54008DAB7270CCE4382E5BF90A8C737D218B4F0D2DA9C29CF827",
            password);



    }

    public static void initialPart(String stringB) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        String P = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6";
        P += "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0";
        P += "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70";
        P += "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0";
        P += "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708";
        P += "DF1FB2BC2E4A4371";

        String G = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F";
        G += "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213";
        G += "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1";
        G += "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A";
        G += "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24";
        G += "855E6EEB22B3B2E5";

        BigInteger BIp = new BigInteger(P,16);
        BigInteger BIg = new BigInteger(G,16);


        //set a random to "a"
        Random r = new Random();


        BigInteger a;
        do {
            a = new BigInteger(BIp.bitLength(), r);
        } while (a.compareTo(BIp) >= 0);


        //this is my random a,  chosen in some point...
        a = new BigInteger("7243620624371142330125376795082688156621909160984356014312981521550975640611062002133037179075557612708377254705697181236294296046125400456530339642610029701603030433427192498989138662100290070157218616232841871705301444347404971403119187881238095552035327654915788748397201977722496393712567080043480615720");

        // A = g^a mod p
        BigInteger A = (BIg.modPow(a,BIp));

        //this is my received B
        BigInteger B = new BigInteger(stringB,16);

        System.out.println("=========Primeira Parte===========");
        System.out.println("a: " + toHex(a.toByteArray()));
        System.out.println("A: " + toHex(A.toByteArray()));
        System.out.println("B: " + toHex(B.toByteArray()));

        //V = B^a mod p
        BigInteger V = (B.modPow(a,BIp));
        MessageDigest algorithm = MessageDigest.getInstance("SHA-256");
        System.out.println("V: "  + toHex(V.toByteArray()));

        //S = SHA256(V)
        S = algorithm.digest(V.toByteArray());
        System.out.println("S: " + toHex(S));
    }

    public static void finalPart(String msgString, byte[] password) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        System.out.println("=========Segunda Parte===========");
        //this is my received message
        String msg = msgString;
        byte[] msgByte = hexStringToByteArray(msg);

        //params needed to decrypt method
        String algo="AES/CBC/PKCS5Padding";
        byte[] cypherText = Arrays.copyOfRange(msgByte,16,msgByte.length);
        byte[] IV = Arrays.copyOfRange(msgByte, 0, 16);


        String decrypt = decrypt(algo, cypherText,IV,password);
        System.out.println("Message Received: " + decrypt);

        String reversedStr = new StringBuilder(decrypt).reverse().toString();
        System.out.println("Message reversed: " +reversedStr);


        byte[] msgSendByte = encrypt(algo, reversedStr,password);
        //separando em hexa
        String encryptHexa = toHex(msgSendByte);
        System.out.println(encryptHexa);


        byte[] IV2 = Arrays.copyOfRange(msgSendByte, 0, 16);




        String decrypt2 = decrypt(algo, hexStringToByteArray(encryptHexa), IV2, password);

        System.out.println(decrypt2);


    }
    //https://www.baeldung.com/java-aes-encryption-decryption
    public static String decrypt(String algo, byte[] cipherText, byte[] iv, byte[] password) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        IvParameterSpec IV = new IvParameterSpec(iv);
        SecretKeySpec key = new SecretKeySpec(password,"AES");
        Cipher cipher = Cipher.getInstance(algo);

        cipher.init(Cipher.DECRYPT_MODE, key, IV);
        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText);
    }

    ////https://www.baeldung.com/java-aes-encryption-decryption
    public static byte[] encrypt(String algo, String cipherText, byte[] password) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        //IvParameterSpec IV = new IvParameterSpec(iv);
        byte[] iv1 = new byte[16];
        new SecureRandom().nextBytes(iv1);
        iv1Glob = iv1;
        IvParameterSpec IV = new IvParameterSpec(iv1);

        SecretKeySpec key = new SecretKeySpec(password,"AES");
        Cipher cipher = Cipher.getInstance(algo);

        cipher.init(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(cipherText.getBytes());
    }

    //https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java/140861#140861
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    //https://stackoverflow.com/questions/332079/in-java-how-do-i-convert-a-byte-array-to-a-string-of-hex-digits-while-keeping-l/943963#943963
    public static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "x", bi);
    }


    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
