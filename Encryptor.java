import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


/**
 * This class generates a file and encrypts it using AES(CBC, Random IV) using a key generated with RSA.
 * Moreover, the class signs the file and appends the signature to the file.

 *
 */
public class Encryptor {

	private static byte[] signature_RES; //result of signature stored in array

	private  static String ALG_KEY = "AES"; //algorithm key type Symmetric
	
	private  static String ALG_RAND = "SHA1PRNG";//random algorithm
	
	private  static int LEN_IV = 16;//length of IV
	
	private static byte[] IV_bitwise_array = new byte[LEN_IV];//info stored in array
	
	private static SecretKey secretKey; 
	
	private  static int LEN_KEY = 128; //key size   in bits 
	
	private  static String ALG_DIGEST = "SHA1";// Message Digest algorithm
	
	private static String ALG_SIGNATURE = "MD5withRSA";//algorithm signature 
	
	private  static String ALG_KEY_ENCRYPT = "RSA"; // Asymmetric key encryptionALG_SIGNATURESIGNATURE_ALGORITHEM_PROVIDER
	
	private KeyGenerator generator;   // key generator
	
	private static byte[] secretKeyEncrypted; //encryption key byte array 
	
	private  static String ALG_ECRYPT = "AES/CBC/PKCS5Padding";// algorithm of encryptor
	
	
	private  static String CIPHER_ALGORITHM_PROVIDER = "SunJCE"; // Message cipher algorithm provider
	
	
	private  static String SECURE_RANDOM_PROVIDER = "SUN"; // Secure random algorithm provider 
	
	
	private  static String KEY_ALGORITHM_PROVIDER = "SunJCE";  // Secret Key algorithm provider 
	
	
	private  static String SIGNATURE_ALGORITHEM_PROVIDER = "SunJSSE"; // Signature algorithm provider 
	
	
	private  static String DIGEST_ALGO_PROVIDER = "SUN"; // Message digest algorithm provider
	
	
	private  static String ENCRYPT_KEY_ALGORITHEM_PROVIDER = "SunJCE"; // Algorithm for Asymmetric encryption Provider 
	
	private static Cipher cipher;
	
	private static KeyStore keystore;


	public Encryptor() {

		//initializeKeyGenerator();
		 
		// initialize the keys 
		try {

			generator = KeyGenerator.getInstance(ALG_KEY,KEY_ALGORITHM_PROVIDER);
			generator.init(LEN_KEY);

		} catch (Exception e) {
			System.out.println("Error while creating encryption key : " + e.getMessage());
			System.exit(1);		
		}

		//create the encryption key for the algorithm  specified in KEY_ALGORITHM
		secretKey = generator.generateKey();

		//createRandomIV();
		
		try {
			SecureRandom random = SecureRandom.getInstance(ALG_RAND,SECURE_RANDOM_PROVIDER);
			random.nextBytes(IV_bitwise_array);
		}
		catch (Exception e) {  
			System.out.println("Error while creating random IV  : " + e.getMessage());

			//we need to terminate 
			System.exit(1);
		}

		//initializeCipher();
		
		
		try {

			cipher = Cipher.getInstance(ALG_ECRYPT,CIPHER_ALGORITHM_PROVIDER);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV_bitwise_array));

		} catch (Exception e) {
			System.out.println("Error while creating encryption cypher" + e.getMessage());
			System.exit(1);     
		}
		
	}

	/**
	 * The main method receives these args
	 * 1. file to encrypt location
	 * 2. location to save encrypted file
	 * 3. JKS file
	 * 4. JKS Alias
	 * 5. JKS Password
	 * 6. JKS Alias of other side's Keystore
	 * 
	 * Then the method generates the encrypted file(as described above) and saves it to disk.
	 */
	public static void main(String[] args) {

		//check we received the necessary arguments
		if(args.length < 7) {
			System.out.println("Not enough arugments inputed to the program, please input 6 arguments as specified");
			return;
		}
		
		File fileToEncrypt = new File(args[0]);
		File encryptedFile = new File(args[1]);
		File keyStoreFile = new File(args[2]);
		String keyStoreAlias = args[3];
		String keyStorePassword = args[4];
		String keyStoreAlias_other = args[5];
		File configFile = new File(args[6]);

		 Properties config = new Properties();
			try {
				config.load(new FileReader(configFile));
				ALG_RAND= config.getProperty("RandomAlgorithm");
				ENCRYPT_KEY_ALGORITHEM_PROVIDER = config.getProperty("KeyEncryptAlgoProvider");
				DIGEST_ALGO_PROVIDER = config.getProperty("DigestAlgoProvider");
				ALG_KEY = config.getProperty("KeyAlgorithm");
				ALG_DIGEST = config.getProperty("DigestAlgorithm");
				SECURE_RANDOM_PROVIDER = config.getProperty("SecureRandomAlgorithmProvider");
				KEY_ALGORITHM_PROVIDER = config.getProperty("SecretKeyAlgorithmProvider");
				ALG_SIGNATURE = config.getProperty("SignatureEncryptionAlgorithm");
				ALG_KEY_ENCRYPT = config.getProperty("KeyEncryptionAlgorithm");
				CIPHER_ALGORITHM_PROVIDER = config.getProperty("MessageEncryptAlgoProvider");
				ALG_ECRYPT = config.getProperty("EncryptionAlgorithmForFile");
				SIGNATURE_ALGORITHEM_PROVIDER = config.getProperty("SignatureEncryptAlgoProvider");			
			}
			catch (Exception e) {
				System.out.println("Encountered an error while reading the specified configuation file. Error details: " + e.getMessage());
				
			}

		Encryptor encryptor = new Encryptor();

		

		if(! Encryptor.check_the_arguments(args, fileToEncrypt, encryptedFile, keyStoreFile))
			return;

		JKSParameters keyStoreConfig = new JKSParameters(keyStoreFile, keyStoreAlias, keyStorePassword,keyStoreAlias_other);
		
		
		
		// Load and Initialize Key Store according to input parameters
		if(! Encryptor.loadKeyStore(keyStoreConfig))
			return;

		try
		{
			if(! Encryptor.encryptKey(keyStoreConfig))
				return;

			if(! encryptor.propegateSignatureForFile(fileToEncrypt, keyStoreConfig))
				return;

			if(! Encryptor.EncryptFileContent(fileToEncrypt, encryptedFile))
				return;

			//now we write a configuration file as described in instructions for the decryptor to use
			Encryptor.WriteConfigFile();

			System.out.println("File has been successfully encrypted: " + fileToEncrypt);

		}
		catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
	
	/**
	 * method writes all arguments needed for decryptor to a config file
	 */
	private static void WriteConfigFile() {
		try {
			FileOutputStream fos = new FileOutputStream("config.cfg");

			Properties configFile = new Properties();

			configFile.setProperty("IV", convertbytesToHexaString(IV_bitwise_array));
			configFile.setProperty("DigestAlgorithm", ALG_DIGEST);
			configFile.setProperty("EncryptionAlgorithmForFile", ALG_ECRYPT);
			configFile.setProperty("KeyAlgorithm", ALG_KEY);
			configFile.setProperty("KeyEncryptionAlgorithm", ALG_KEY_ENCRYPT);
			configFile.setProperty("SignatureEncryptionAlgorithm", ALG_SIGNATURE);
			configFile.setProperty("EncryptedKey", convertbytesToHexaString(secretKeyEncrypted));
			configFile.setProperty("Signature", convertbytesToHexaString(signature_RES));
			configFile.setProperty("MessageEncryptAlgoProvider", CIPHER_ALGORITHM_PROVIDER);
			configFile.setProperty("SecureRandomAlgorithmProvider", SECURE_RANDOM_PROVIDER);
			configFile.setProperty("SecretKeyAlgorithmProvider ", KEY_ALGORITHM_PROVIDER);
			configFile.setProperty("KeyEncryptAlgoProvider", ENCRYPT_KEY_ALGORITHEM_PROVIDER);
			configFile.setProperty("SignatureEncryptAlgoProvider", SIGNATURE_ALGORITHEM_PROVIDER);
			configFile.setProperty("DigestAlgoProvider", DIGEST_ALGO_PROVIDER);

			configFile.store(fos, null);
		} catch (Exception e) {
			
			System.out.println("Configuration file proccessing has encountered an error. Details: " + e.getMessage());
		}

	}
	
	/**
	 * Method encrypts the private key using the public one
	 */
	private static boolean encryptKey(JKSParameters keyStoreConfig) {

		try{

			// Get public key for assymetric encryption
			PublicKey publicKey =	keystore.getCertificate(keyStoreConfig.keyStoreAlias_other).getPublicKey();

			//get an instance of the RSA cypher and encrypt the key using the public key in the keystore
			Cipher keyEncryptionCipher = Cipher.getInstance(ALG_KEY_ENCRYPT,ENCRYPT_KEY_ALGORITHEM_PROVIDER); //Asymmetric
			keyEncryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			secretKeyEncrypted = keyEncryptionCipher.doFinal(secretKey.getEncoded());
		}
		catch(Exception e )
		{
			System.out.println ("Assymetric encryption of the cipher key encountered an error: " + e.getMessage());
			return false;
		}

		return true;
	}

	/***
	 * Encrypt file using cipher
	 */
	private static boolean EncryptFileContent(File fileToEncrypt, File encryptedFile) throws IOException 
	{
		//we initialize out of the try to close them in a finally block
		CipherOutputStream outputStream = null;
		FileInputStream inputStream = null;  

		try {

			//stream to use
			inputStream = new FileInputStream(fileToEncrypt);
			outputStream = new CipherOutputStream(new FileOutputStream(encryptedFile), cipher);

			byte[] buffer = new byte[512]; //512 block size is arbitrary
			int readBytes;

			//read all file until we reach EOF
			while((readBytes = inputStream.read(buffer)) >= 0)
			{
				outputStream.write(buffer, 0, readBytes);
			}

		} catch(Exception e) {

			System.out.println("Error Encrypting file. Details: " + e.getMessage());
			return false;

		} finally {

			if (inputStream != null) {
				inputStream.close();
			}
			if (outputStream != null) {
				outputStream.close();
			}
		}

		return true;
	}

	/**
	 * creates instance of key store according to input parameters
	 */
	private static boolean loadKeyStore(JKSParameters keyStoreConfig) 
	{
		try 
		{
			keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream(keyStoreConfig.keyStoreFile), keyStoreConfig.keyStorePassword.toCharArray());
			return true;

		} catch (Exception e) {
			System.out.println(" Error while trying to load keystore file , details: " + e.getMessage());
			return false;
		}
	}






	/***
	 * Retrieves file's bytes
	 */
	private static byte[] FileToBytes(File file) {

		try {

			RandomAccessFile rfa = new RandomAccessFile(file, "r");
			byte[] fileToEncryptBytes = new byte[(int)rfa.length()];
			rfa.read(fileToEncryptBytes);
			rfa.close();

			return fileToEncryptBytes;
		}
		catch (Exception e) {
			System.out.println("Program encountered Error while  reading encrypted file. Error Details: " + e.getMessage());
			return null;
		}
	}
	
	/**
	 * creates signature for encrypted file
	 */
	private boolean propegateSignatureForFile(File fileToEncrypt, JKSParameters keyStoreConfig ) {

		try{

			//Read file's Bytes
			byte[] fileToEncryptBytes = FileToBytes(fileToEncrypt);

			if(fileToEncrypt == null) {
				return false;
			}

			//create a digest
			MessageDigest messageDigest = MessageDigest.getInstance(ALG_DIGEST,DIGEST_ALGO_PROVIDER);
			messageDigest.update(fileToEncryptBytes);


			// Get entry from keystore and create the private key for signature
			PrivateKeyEntry keyEntry = (PrivateKeyEntry) keystore.getEntry(keyStoreConfig.keyStoreAlias, 
					new KeyStore.PasswordProtection(keyStoreConfig.keyStorePassword.toCharArray()));
			PrivateKey privateKey = keyEntry.getPrivateKey();

			createSignature(privateKey, messageDigest.digest());

			return true;

		} catch (Exception e) {
			System.out.println(" Signing File Error: " + e.getMessage());
			return false;
		}
	}
	
	/**
	 * signs the file
	 */
	private void createSignature(PrivateKey privateKey, byte[] fileDigest) 
			throws NoSuchAlgorithmException, NoSuchProviderException,InvalidKeyException, SignatureException {

		Signature signatureGenerator = Signature.getInstance(ALG_SIGNATURE,SIGNATURE_ALGORITHEM_PROVIDER);
		signatureGenerator.initSign(privateKey);
		signatureGenerator.update(fileDigest);

		//sign the digest
		signature_RES = signatureGenerator.sign();
	}
	
	/**
	 * validates encryptor receives all necessary arguments 
	 */
	private static boolean check_the_arguments(String[] args, File fileToEncrypt, File encryptedFile, File keyStoreFile) {


		if(! fileToEncrypt.exists()) {
			System.out.println("File to encrypt does not exist");
			return false;
		}

		if(encryptedFile.exists()) {
			System.out.println("Deleting the older encrypted file which is in location specified : (" + args[1] + ")");

			try{

				encryptedFile.delete();
			}
			catch(Exception e) {
				System.out.println("encountered an error while deleting the encrypted file");
				return false;
			}
		}

		if(! keyStoreFile.exists()) {
			System.out.println("the Keystore file specified does not exist");
			return false;
		}

		return true;
	}
	
	/**
	 * receives byte array converts it to hex string
	 */
	private static String convertbytesToHexaString(byte[] byteArray) {
		
	    final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    
	    char[] hexChars = new char[byteArray.length * 2];
	    int v;
	    
	    for ( int j = 0; j < byteArray.length; j++ ) {
	        v = byteArray[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    
	    return new String(hexChars);
	}
}
