import java.io.File;

/***
 * Contains info regarding JKS parameters

 */
public class JKSParameters 
{		
	
	public File keyStoreFile; //file name variable
	
	public String keyStoreAlias; //key store name
	
	public String keyStorePassword; //key store pass
	
	public String keyStoreAlias_other; //store the alias of the other side's JKS
	
	
	
	
		JKSParameters(File keyStoreFile, String keyStoreAlias, String keyStorePassword,String keyStoreAlias_other) {
			this.keyStoreFile = keyStoreFile;
			this.keyStoreAlias = keyStoreAlias; 
			this.keyStorePassword = keyStorePassword;
			this.keyStoreAlias_other= keyStoreAlias_other;
		}

	
}