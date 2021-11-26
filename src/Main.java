import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;


public class Main {
public static void main(String[] args) throws Exception {
//	RSA rsa = new RSA();
//	rsa.genkey();
//	byte[] ciphertext =rsa.encrypt("Đại học nxxxxxông lâm TP.HCM");
//	String text= new String(ciphertext);
//	System.out.println("Ma hoa: "+text);
//	Key key =rsa.getPrivateKey();
//	String plaintext =rsa.decrypt(ciphertext, key);
//	System.out.println("Giai ma: "+plaintext);
	RSAFile rsaFile = new RSAFile();
//	rsaFile.doGenkey("F:\\test\\rsaFile");	
	PublicKey key  =rsaFile.readPublicKey("F:\\test\\rsaFile\\public.key");
//	PrivateKey prikey  =rsaFile.readPrivateKey("F:\\test\\rsaFile\\private.key");
//	RSAFile.doEncryptRSAWithAES(prikey, "F:\\test\\rsaFile\\pikachu.zip", "F:\\test\\rsaFile\\pikachu.zipe");
RSAFile.doDeCryptRSAWithAES(key, "F:\\test\\rsaFile\\pikachu.zipe", "F:\\test\\rsaFile\\pikachu1.zip");
}
}
