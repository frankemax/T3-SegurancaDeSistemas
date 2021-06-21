import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        initialPart();


    }

    public static void initialPart() throws NoSuchAlgorithmException {
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

        System.out.println(BIp);
        //System.out.println(BIg);


        //set a random to "a"
        Random r = new Random();


        BigInteger a;
        do {
            a = new BigInteger(BIp.bitLength(), r);
        } while (a.compareTo(BIp) >= 0);


        //this is my random a,  chosen in some point...
        a = new BigInteger("7243620624371142330125376795082688156621909160984356014312981521550975640611062002133037179075557612708377254705697181236294296046125400456530339642610029701603030433427192498989138662100290070157218616232841871705301444347404971403119187881238095552035327654915788748397201977722496393712567080043480615720");
        //System.out.println(a);


        BigInteger A = (BIg.modPow(a,BIp));

        System.out.println(A.toString(16));

        //this is my received B
        BigInteger B = new BigInteger("383F8C3FED2160F863AE303799FA99C738BA60D88BB26BAC672584D39584CA13E13D48365FE025A37E73D67527B4A6AE44EEB302D3A92BE991F8C7B42CD07D3926365291C7BA7FA59F2F5B5034167B1984AEB866A48F997D46819581A10B62E69806FF988DC69A6694ACE451FE687EEAF43F96678836C39F77577938E15449CE",16);

        System.out.println("A: " + A);
        System.out.println("B: " + B);

        BigInteger V = (BIg.modPow(a,BIp));

        MessageDigest algorithm = MessageDigest.getInstance("SHA-256");

        byte[] S = algorithm.digest(V.toByteArray());

        System.out.println("S: " + toHex(S));
        byte[] password = Arrays.copyOfRange(S,0,16);
        System.out.println("First 128bits / 32hex: " +toHex(password));

    }

    //https://stackoverflow.com/questions/332079/in-java-how-do-i-convert-a-byte-array-to-a-string-of-hex-digits-while-keeping-l/943963#943963
    public static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "x", bi);
    }
}
