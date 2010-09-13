package to.networld.soap.security.common;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import to.networld.soap.security.interfaces.ICredential;
import to.networld.soap.security.keystores.JKSKeyStore;

/**
 * @author Alex Oberhauser
 *
 */
public class Credential implements ICredential {
	private final String pkcs12alias;
	private final String pkcs12file;
	private final String pkcs12password;
	
	private final JKSKeyStore keystore;
	
	public Credential(String _pkcs12file, String _pkcs12alias, String _pkcs12password,
			String _publicKeystoreFile, String _publicKeystorePassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		this.pkcs12file = _pkcs12file;
		this.pkcs12alias = _pkcs12alias;
		this.pkcs12password = _pkcs12password;
		
		this.keystore = new JKSKeyStore(_publicKeystoreFile, _publicKeystorePassword);
	}

	/**
	 * @see to.networld.soap.security.interfaces.ICredential#getPKCS12Alias()
	 */
	@Override
	public String getPKCS12Alias() { return this.pkcs12alias; }

	/**
	 * @see to.networld.soap.security.interfaces.ICredential#getPKCS12File()
	 */
	@Override
	public String getPKCS12File() { return this.pkcs12file; }

	/**
	 * @see to.networld.soap.security.interfaces.ICredential#getPKCS12Password()
	 */
	@Override
	public String getPKCS12Password() { return this.pkcs12password; }

	/**
	 * @see to.networld.soap.security.interfaces.ICredential#getPublicKeystore()
	 */
	@Override
	public KeyStore getPublicKeystore() { return this.keystore.getKeyStore(); }

}
