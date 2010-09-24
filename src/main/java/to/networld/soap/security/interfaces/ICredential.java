package to.networld.soap.security.interfaces;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * @author Alex Oberhauser
 *
 */
public interface ICredential {
	
	public String getPKCS12File();
	public String getPKCS12Alias();
	public String getPKCS12Password();
	
	public KeyStore getPublicKeystore();
	
	public String getBase64X509Certificate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException;
	
}
