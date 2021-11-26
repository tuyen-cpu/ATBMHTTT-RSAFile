import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import com.sun.xml.internal.stream.util.BufferAllocator;

public class RSA {
	private KeyPair keypair;
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public byte[] encrypt(String text) throws Exception {
		if (publicKey == null)
			genkey();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] plaintext = text.getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plaintext);
		return cipherText;
	}

	public String decrypt(byte[] text, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plaintext = cipher.doFinal(text);
		String result = new String(plaintext, "UTF-8");
		return result;
	}
public void EncryptFile(String sourceFile,String destFile) throws Exception{
	File file = new File(sourceFile);
	if(file.exists()){
		if(publicKey==null)genkey();
		Cipher cipher =Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE,publicKey);
		DataInputStream dis =new DataInputStream(new BufferedInputStream(new FileInputStream(file)));
		DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(destFile)));
		
		byte[] input =new byte[256];
		
		long length =file.length();
		int byteRead=0;
		while(length>0){
			byteRead =dis.read(input);
			byte[] cipherText =cipher.doFinal(input,0,byteRead);
			dos.write(cipherText);
			dos.flush();
			length = length-byteRead;
		}
		dos.close();
		dis.close();
		System.out.println("File is encrypted");
	}else{
		System.out.println("Source file is not existed");
	}
}
	public void genkey() {
		KeyPairGenerator keyGenerator=null;
		try{
			keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(2848);
			keypair =keyGenerator.generateKeyPair();
			publicKey =keypair.getPublic();
			privateKey = keypair.getPrivate();
			
		}catch(NoSuchAlgorithmException e){
			e.printStackTrace();
		}
	}

	public KeyPair getKeypair() {
		return keypair;
	}

	public void setKeypair(KeyPair keypair) {
		this.keypair = keypair;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
}
