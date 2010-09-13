package to.networld.soap.security.interfaces;

import java.security.KeyStore;

/**
 * @author Alex Oberhauser
 *
 */
public interface ICredential {
	
	public String getPKCS12File();
	public String getPKCS12Alias();
	public String getPKCS12Password();
	
	public KeyStore getPublicKeystore();
	
}
