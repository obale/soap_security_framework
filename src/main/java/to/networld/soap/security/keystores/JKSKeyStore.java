/**
 * SOAP Security Framework
 *
 * Copyright (C) 2010 by Networld Project
 * Written by Alex Oberhauser <oberhauseralex@networld.to>
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>
 */

package to.networld.soap.security.keystores;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Alex Oberhauser
 */
public class JKSKeyStore {
	private final String keystoreFile;
	private final KeyStore keystore;
	
	public JKSKeyStore(String _keystoreFile, String _password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException  {
		this.keystoreFile = _keystoreFile;
		this.keystore = KeyStore.getInstance("JKS");
		this.keystore.load(new FileInputStream(this.keystoreFile), _password.toCharArray());
	}
	
	/**
	 * Returns the X.509 certificate with the given alias from a JKS keystore.
	 * 
	 * @param _alias The name of the certificate.
	 * @return The X.509 certificate.
	 * @throws KeyStoreException 
	 * @throws UnrecoverableEntryException 
	 * @throws NoSuchAlgorithmException 
	 */
	public X509Certificate getX509Certificate(String _alias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException  {
        KeyStore.TrustedCertificateEntry keyEntry = (KeyStore.TrustedCertificateEntry) this.keystore.getEntry(_alias, null);
        return (X509Certificate) keyEntry.getTrustedCertificate();
	}
	
	public KeyStore getKeyStore() { return this.keystore; }
	
}
