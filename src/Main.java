import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class Main {
    public static byte[] S;


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException {
        //B received
        initialPart("383F8C3FED2160F863AE303799FA99C738BA60D88BB26BAC672584D39584CA13E13D48365FE025A37E73D67527B4A6AE44EEB302D3A92BE991F8C7B42CD07D3926365291C7BA7FA59F2F5B5034167B1984AEB866A48F997D46819581A10B62E69806FF988DC69A6694ACE451FE687EEAF43F96678836C39F77577938E15449CE");
        byte[] password = Arrays.copyOfRange(S, 0, 16);
        //first message received
        finalPart("BF141DC52E3AA3D6ED1E2508E7BE1176A8C6C447C8AB3F2B389FC932352ECF0CE13A9C75AFBB5A81320723B70F69D01457E50BA107CEB7146B016382BD75D39FD38C88FD386F54008DAB7270CCE4382E5BF90A8C737D218B4F0D2DA9C29CF827",
                password);
        //second message received, put in the finalPart() first parameter to read it.
        //750FD410816C35EDC6DEF627A992C3AFF05EBF4CB24361B35B73EC603B225E928185F30DEBA2BD9AC80AFA6CC4877D687472581FE24CC43E8AC3DBA35903973E702D575954EF0560710F9C549F829B8E70EC5B12C60B6972900E950AE34004E4EC49DE8A168958E68A4D6F656B986D7C

    }

    public static void initialPart(String stringB) throws NoSuchAlgorithmException {
        StringBuilder SBp = new StringBuilder();
        SBp.append("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6");
        SBp.append("9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0");
        SBp.append("13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70");
        SBp.append("98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0");
        SBp.append("A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708");
        SBp.append("DF1FB2BC2E4A4371");
        String P = SBp.toString();

        StringBuilder SBg = new StringBuilder();
        SBg.append("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F");
        SBg.append("D6406CFF14266D31266FEA1E5C41564B777E690F5504F213");
        SBg.append("160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1");
        SBg.append("909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A");
        SBg.append("D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24");
        SBg.append("855E6EEB22B3B2E5");
        String G = SBg.toString();

        BigInteger BIp = new BigInteger(P, 16);
        BigInteger BIg = new BigInteger(G, 16);

        Random r = new Random();
        //set a random to "a"
        //assure that a is a number < P and >0
        //https://stackoverflow.com/questions/2290057/how-to-generate-a-random-biginteger-value-in-java
        BigInteger a;
        do {
            a = new BigInteger(BIp.bitLength(), r);
        } while (a.compareTo(BIp) >= 0);

        //this is my random a,  chosen in some point...
        a = new BigInteger("7243620624371142330125376795082688156621909160984356014312981521550975640611062002133037179075557612708377254705697181236294296046125400456530339642610029701603030433427192498989138662100290070157218616232841871705301444347404971403119187881238095552035327654915788748397201977722496393712567080043480615720");

        // A = g^a mod p
        BigInteger A = (BIg.modPow(a, BIp));

        //this is my received B
        BigInteger B = new BigInteger(stringB,16);

        System.out.println("=========Primeira Parte===========");
        System.out.println("a: " + toHex(a.toByteArray()));
        System.out.println("A: " + toHex(A.toByteArray()));
        System.out.println("B: " + toHex(B.toByteArray()));

        //V = B^a mod p
        BigInteger V = (B.modPow(a, BIp));
        MessageDigest algorithm = MessageDigest.getInstance("SHA-256");
        System.out.println("V: " + toHex(V.toByteArray()));

        //S = SHA256(V)
        S = algorithm.digest(V.toByteArray());

        System.out.println("S(first 128bits): " + toHex(S).substring(0, 32));
    }

    public static void finalPart(String msgString, byte[] password) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        System.out.println("=========Segunda Parte===========");
        //this is my received message
        String msg = msgString;
        byte[] msgByte = hexStringToByteArray(msg);

        //params needed to decrypt method
        String algo = "AES/CBC/PKCS5Padding";
        String cypherText = msg.substring(32); //16 bytes
        SecretKeySpec key = new SecretKeySpec(password, "AES");
        IvParameterSpec IV = new IvParameterSpec(Arrays.copyOfRange(msgByte, 0, 16));

        //decrypting...
        String decrypt = decrypt(algo, cypherText, IV, key);
        System.out.println("Message Received: " + decrypt);

        //follow the instructions...
        String reversedStr = new StringBuilder(decrypt).reverse().toString();
        System.out.println("Message reversed: " + reversedStr);

        //params needed to encrypt method
        byte[] iv2 = new byte[16];
        new SecureRandom().nextBytes(iv2);
        SecretKeySpec key2 = new SecretKeySpec(password, "AES");

        //encrypting
        byte[] msgSendByte = encrypt(algo, reversedStr, key2);

        //change to hex and send
        String encryptHexa = toHex(msgSendByte);
        System.out.println("Encrypted hexa: " + encryptHexa);


        //decrypting the crypted message, to assure that is correct before sending to professor... uncomment to check
        //String algo3="AES/CBC/PKCS5Padding";
        //String cypherText3 = encryptHexa.substring(32); //16 bytes
        //SecretKeySpec key3 = new SecretKeySpec(password,"AES");
        //IvParameterSpec IV3 = new IvParameterSpec(Arrays.copyOfRange(msgSendByte, 0, 16));
        //String decrypt2 = decrypt(algo3, cypherText3, IV3, key3);
        //System.out.println("Decrypt sent message : " + decrypt2);


    }

    //https://www.baeldung.com/java-aes-encryption-decryption
    public static String decrypt(String algorithm, String cipherText, IvParameterSpec iv, SecretKey key)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        byte[] cipherTextBytes = hexStringToByteArray(cipherText);
        Cipher cipher = Cipher.getInstance(algorithm);

        //i don't know if it was necessary, but i removed the base64 and change it to []byte... it was not working here
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(cipherTextBytes);

        return new String(plainText);
    }

    ////https://www.baeldung.com/java-aes-encryption-decryption
    public static byte[] encrypt(String algorithm, String cipherText, SecretKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        //generate a random IV
        byte[] iv1 = new byte[16];
        new SecureRandom().nextBytes(iv1);
        IvParameterSpec IV = new IvParameterSpec(iv1);

        //i don't know if it was necessary, but i removed the base64 and change it to []byte... it was not working here
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, IV);

        //concatenate the [IV][msg]
        byte[] cipherArray = cipher.doFinal(cipherText.getBytes());
        byte[] result = new byte[16 + cipherArray.length];
        System.arraycopy(iv1, 0, result, 0, 16);
        System.arraycopy(cipherArray, 0, result, 16, cipherArray.length);

        return result;
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

    //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
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
