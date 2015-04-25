import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/***
 * The Decryptor class decrypts the file generated initially by the encryptor class

 *
 */
public class Decryptor {


	private static String ALG_DIGEST; //message digest algorithm

	private static String ALG_SIGNATURE; //algorithm for signature of message digest
	
	private static byte[] resultSignature;  //result of signature of message digest

	private final static int LEN_IV = 16; //length of IV

	private static byte[] IV_bitwise_array = new byte[LEN_IV]; //info stored in array

	private static String ALG_KEY; //key algorithm
	
	private static String ALG_ENCRYPT_KEY; //algorithm for encrypted key

	private static byte[] secretKeyEncrypted; //secret key in encryption
	
	private static String ALG_ENCRYPT; //encryption algorithm for secret key

	private static KeyStore keystore; //JKS
	
	private static String CIPHER_ALGORITHM_PROVIDER; // Message cipher algorithm provider
	
	private static String SECURE_RANDOM_PROVIDER ; // Secure random algorithm provider 
	
	
	private static String KEY_ALGORITHM_PROVIDER ;  // Secret Key algorithm provider 
	
	
	private static String SIGNATURE_ALGORITHEM_PROVIDER; // Signature algorithm provider 
	
	
	private static String DIGEST_ALGO_PROVIDER ; // Message digest algorithm provider
	
	
	private static String ENCRYPT_KEY_ALGORITHEM_PROVIDER ; // Algorithm for Asymmetric encryption Provider 

	/**
	 * Method does the following:
	 * 1. receives command line arguments necessary
	 * 2. reads keystore and config file created in the encryptor class
	 * 3. decrypts the file
	 * 4. calculates the file digest, encrypts it (creates signature) and compares it with the original result
	 */
	public static void main(String[] args) {

		//validate received necessary arguments
		if(args.length < 7) {
			System.out.println("Not enought arguments entered to program");
			return;
		}

		File fileToDecrypt = new File(args[0]);
		File decryptedFile = new File(args[1]);
		File keyStoreFile = new File(args[2]);
		String keyStoreAlias = args[3];
		String keyStorePassword = args[4];
		File configFile = new File(args[5]);
		String keyStoreAlias_other = args[6];

		try{
			Decryptor decryptor = new Decryptor();

			if(! Decryptor.validateArguments(args, fileToDecrypt, decryptedFile, keyStoreFile, configFile))
				return;

			JKSParameters keyStoreConfig = new JKSParameters(keyStoreFile, keyStoreAlias, keyStorePassword,keyStoreAlias_other);

			if(!decryptor.init(keyStoreConfig, configFile))
				return;
			
			//decrypt the file and print it to the specified output and to console.
			PrintWriter out = new PrintWriter(decryptedFile);
			byte[] decryptResultBytes = decryptFile(fileToDecrypt, keyStoreConfig);
			String decryptResult = new String(decryptResultBytes);
			System.out.println(decryptResult);
			out.print(decryptResult);
			out.close();
			
			//now verify the result's signature
			verifyFileSignature(keyStoreConfig, decryptResultBytes);
		}
		catch (Exception e) {
			System.out.println("Encountered an error with decrypting the file. Error details: " + e.getMessage());
		}
	}
	
	/***
	 * Method validates all input arguments given in command line

	 */
	private static boolean validateArguments(String[] args, File fileToDecrypt, File decryptedFile, File keyStoreFile, File configFile) {

		System.out.println("Checking the file arguments.");

		if(! fileToDecrypt.exists()) {
			System.out.println("File to decrypt does not exist");
			return false;
		}

		if(decryptedFile.exists()) {
			System.out.println("Deleting former file which  currently in location of decrypted file(" + args[1] + ")");

			try{

				decryptedFile.delete();
			}
			catch(Exception e) {
				System.out.println("there was an issue deleting the decrypted file");
				return false;
			}
		}

		if(! keyStoreFile.exists()) {
			System.out.println("Keystore file specified does not exist.");
			return false;
		}

		if(! configFile.exists()) {
			System.out.println("Config file specified does not exist. Please validate its location and try again");
			return false;
		}

		return true;
	}
	
	/**
	 * method initializes the parameters the decryptor needs by reading keystore and configuration file into memory

	 */
	private boolean init(JKSParameters keyStoreConfig, File configFile) {
		boolean bol,bola;
		/** loads the configuration file containing info from the encryptor results **/
		try {

			keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream(keyStoreConfig.keyStoreFile), 
					keyStoreConfig.keyStorePassword.toCharArray());

		} catch (Exception e) {
			System.out.println("Could not load specified KeyStore. Trying fixing input argumets. Error Details: " + e.getMessage());
			bol =  false;
		}

		 bol = true;
		 /** reads to memory the key store specified in command line  **/
		 Properties config = new Properties();
			try {
				config.load(new FileReader(configFile));

				ALG_DIGEST = config.getProperty("DigestAlgorithm");
				ALG_ENCRYPT = config.getProperty("EncryptionAlgorithmForFile");
				ALG_KEY = config.getProperty("KeyAlgorithm");
				ALG_ENCRYPT_KEY = config.getProperty("KeyEncryptionAlgorithm");
				ALG_SIGNATURE = config.getProperty("SignatureEncryptionAlgorithm");
				secretKeyEncrypted = hexStringToByteArray(config.getProperty("EncryptedKey"));
				resultSignature = hexStringToByteArray(config.getProperty("Signature"));
				IV_bitwise_array = hexStringToByteArray(config.getProperty("IV"));
				CIPHER_ALGORITHM_PROVIDER = config.getProperty("MessageEncryptAlgoProvider");
				SECURE_RANDOM_PROVIDER = config.getProperty("SecureRandomAlgorithmProvider");
				KEY_ALGORITHM_PROVIDER = config.getProperty("SecretKeyAlgorithmProvider");
				DIGEST_ALGO_PROVIDER = config.getProperty("DigestAlgoProvider");
				ENCRYPT_KEY_ALGORITHEM_PROVIDER = config.getProperty("KeyEncryptAlgoProvider");
				SIGNATURE_ALGORITHEM_PROVIDER = config.getProperty("SignatureEncryptAlgoProvider");
				bola= true;
			}
			catch (Exception e) {
				System.out.println("Encountered an error while reading the specified configuation file. Error details: " + e.getMessage());
				bola= false;
			}
		

		return (bol && bola);

	}
	
	/*** 
	 * Method verifies that the signature given in the config file matches the decrypted file signature

	 */
	private static void verifyFileSignature(JKSParameters keyStoreConfig, byte[] decryptResult) {
		try {
			
			//retrieve public key for signature verification
			PublicKey publicKey =	keystore.getCertificate(keyStoreConfig.keyStoreAlias_other).getPublicKey();

			
			// create the message digest we will compare to the one in the config file
			MessageDigest messageDigest = MessageDigest.getInstance(ALG_DIGEST,DIGEST_ALGO_PROVIDER);
			messageDigest.update(decryptResult);
			byte[] digest = messageDigest.digest();
			
			//sign the digest
			Signature signature = Signature.getInstance(ALG_SIGNATURE,SIGNATURE_ALGORITHEM_PROVIDER);
			signature.initVerify(publicKey);
			signature.update(digest);
			
			//last, compare it to the original
			System.out.println("file's signature match source singnature: " + (signature.verify(resultSignature) ? "YES" : "False"));
			
		} 
		catch (Exception e) 
		{
			System.out.println("Could verify the file's intergrity. Error details: " + e.getMessage());
		}
	}
	
	/**
	 * decrypts the input file
	 */
	private static byte[] decryptFile(File fileToDecrpyt, JKSParameters keyStoreConfig ) {
		try{
			Cipher cipher = Cipher.getInstance(ALG_ENCRYPT_KEY,ENCRYPT_KEY_ALGORITHEM_PROVIDER);


			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keystore.getEntry(keyStoreConfig.keyStoreAlias, 
					new KeyStore.PasswordProtection(keyStoreConfig.keyStorePassword.toCharArray()));
			PrivateKey privateKeyEncrypted = privateKeyEntry.getPrivateKey();

			//decrpyt private key
			cipher.init(Cipher.DECRYPT_MODE, privateKeyEncrypted);
			SecretKey privateKey = new SecretKeySpec(cipher.doFinal(secretKeyEncrypted), ALG_KEY);

			//now, we init the cipher to use file's encryption algorithm(using IV and key)
			cipher = Cipher.getInstance(ALG_ENCRYPT,CIPHER_ALGORITHM_PROVIDER);
			cipher.init(Cipher.DECRYPT_MODE, privateKey, new IvParameterSpec(IV_bitwise_array));

			//read all file's bytes and decrpy its
			RandomAccessFile f = new RandomAccessFile(fileToDecrpyt, "r");
			byte[] fileBytes = new byte[(int)f.length()];
			f.read(fileBytes);
			f.close();

			return cipher.doFinal(fileBytes);

		} catch (Exception e) {
			System.out.println("Could not decrypt the file. Error details: " + e.getMessage());
			return null;
		}
	}
	

	


	/**
	 * Converts hex string to a byte array

	 */
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
}
