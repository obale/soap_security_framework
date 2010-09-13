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

package to.networld.soap.security.security;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;
import java.util.Vector;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;

import to.networld.soap.security.callback.CallbackHandlerImpl;
import to.networld.soap.security.interfaces.ICredential;
import to.networld.soap.security.interfaces.ISecSOAPMessage;

/**
 * Implementation of {@link ISecSOAPMessage}.
 * 
 * @author Alex Oberhauser
 */
public class SecSOAPMessage implements ISecSOAPMessage {
	private final SOAPMessage message;
	private static final WSSecurityEngine secEngine = new WSSecurityEngine();
	
	protected SecSOAPMessage(SOAPMessage _message) {
		this.message = _message;
	}

	/**
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#checkSecurityConstraints(to.networld.soap.security.interfaces.ICredential)
	 */
	@Override
	public Vector<?> checkSecurityConstraints(ICredential _credential) 
			throws SOAPException, CredentialException, IOException {
		Document doc = this.message.getSOAPPart().getEnvelope().getOwnerDocument();
		
		Merlin sigCrypto = new Merlin(new Properties());
		sigCrypto.setKeyStore(_credential.getPublicKeystore());
		
		Properties prop = new Properties();
		prop.put("org.apache.ws.security.crypto.merlin.file", _credential.getPKCS12File());
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "PKCS12");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.password", _credential.getPKCS12Password());
	    Merlin decCrypto = new Merlin(prop);
	    
	    CallbackHandlerImpl cb = new CallbackHandlerImpl();
	    cb.setLoginCredentials(_credential.getPKCS12Alias(), _credential.getPKCS12Password());
	    
	    return secEngine.processSecurityHeader(doc, null, cb, sigCrypto, decCrypto);
	}

	/**
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#encryptSOAPMessage(java.util.Vector, to.networld.soap.security.interfaces.ICredential, java.lang.String)
	 */
	@Override
	public void encryptSOAPMessage(Vector<WSEncryptionPart> _encryptionParts, ICredential _credential,
			String _alias) throws SOAPException, CredentialException, IOException {
		SOAPEnvelope soapEnvelope = this.message.getSOAPPart().getEnvelope();
		
	    Merlin crypto = new Merlin(new Properties());
	    crypto.setKeyStore(_credential.getPublicKeystore());
	    
	    WSSecEncrypt encrypt = new WSSecEncrypt();
	    encrypt.setEncKeyValueType(WSConstants.AES_256);
	    encrypt.setUserInfo(_alias);

	    Document doc = soapEnvelope.getOwnerDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.setMustUnderstand(true);
        secHeader.insertSecurityHeader(doc);
        
        encrypt.setParts(_encryptionParts);
		encrypt.build(doc, crypto, secHeader);
		
		this.message.saveChanges();
	}

	/**
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#signSOAPMessage(java.util.Vector, to.networld.soap.security.interfaces.ICredential)
	 */
	@Override
	public void signSOAPMessage(Vector<WSEncryptionPart> _signingParts, ICredential _credentials) throws SOAPException, CredentialException, IOException {
		SOAPEnvelope soapEnvelope = this.message.getSOAPPart().getEnvelope();

		Properties prop = new Properties();
		prop.put("org.apache.ws.security.crypto.merlin.file", _credentials.getPKCS12File());
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "PKCS12");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.password", _credentials.getPKCS12Password());

	    Merlin crypto = new Merlin(prop);

	    WSSecSignature sign = new WSSecSignature();
	    sign.setUserInfo(_credentials.getPKCS12Alias(), _credentials.getPKCS12Password());
	    sign.setDigestAlgo(DigestMethod.SHA1);
	    
	    Document doc = soapEnvelope.getOwnerDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.setMustUnderstand(true);
        secHeader.insertSecurityHeader(doc);
        
        sign.setParts(_signingParts);
        sign.build(doc, crypto, secHeader);
        
		this.message.saveChanges();
	}

	/**
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#getSOAPMessage()
	 */
	@Override
	public SOAPMessage getSOAPMessage() { return this.message; }

	/**
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#printSOAPMessage(java.io.OutputStream)
	 */
	@Override
	public void printSOAPMessage(OutputStream _out) throws SOAPException, IOException {
		this.message.writeTo(_out);
	}
}
