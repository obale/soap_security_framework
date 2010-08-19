package to.networld.soap.security.security;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
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
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#checkSecurityConstraints(javax.xml.soap.SOAPMessage, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public Vector<?> checkSecurityConstraints(String _pkcs12File, String _alias, String _password, KeyStore _keystore) 
			throws SOAPException, CredentialException, IOException {
		Document doc = this.message.getSOAPPart().getEnvelope().getOwnerDocument();
		
		Merlin sigCrypto = new Merlin(new Properties());
		sigCrypto.setKeyStore(_keystore);
		
		Properties prop = new Properties();
		prop.put("org.apache.ws.security.crypto.merlin.file", _pkcs12File);
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "PKCS12");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.password", _password);
	    Merlin decCrypto = new Merlin(prop);
	    
	    CallbackHandlerImpl cb = new CallbackHandlerImpl();
	    cb.setLoginCredentials(_alias, _password);
	    
	    return secEngine.processSecurityHeader(doc, null, cb, sigCrypto, decCrypto);
	}

	/**
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#encryptSOAPMessage(javax.xml.soap.SOAPMessage, java.util.Vector, java.security.KeyStore, java.lang.String)
	 */
	@Override
	public void encryptSOAPMessage(Vector<WSEncryptionPart> _encryptionParts, KeyStore _keystore,
			String _alias) throws SOAPException, CredentialException, IOException {
		SOAPEnvelope soapEnvelope = this.message.getSOAPPart().getEnvelope();
		
	    Merlin crypto = new Merlin(new Properties());
	    crypto.setKeyStore(_keystore);
	    
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
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#signSOAPMessage(javax.xml.soap.SOAPMessage, java.util.Vector, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void signSOAPMessage(Vector<WSEncryptionPart> _signingParts, String _pkcs12File, String _alias, 
			String _password) throws SOAPException, CredentialException, IOException {
		SOAPEnvelope soapEnvelope = this.message.getSOAPPart().getEnvelope();

		Properties prop = new Properties();
		prop.put("org.apache.ws.security.crypto.merlin.file", _pkcs12File);
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "PKCS12");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.password", _password);

	    Merlin crypto = new Merlin(prop);

	    WSSecSignature sign = new WSSecSignature();
	    sign.setUserInfo(_alias, _password);
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
	 * @throws IOException 
	 * @throws SOAPException 
	 * @see to.networld.soap.security.interfaces.ISecSOAPMessage#printSOAPMessage(java.io.InputStream)
	 */
	@Override
	public void printSOAPMessage(OutputStream _out) throws SOAPException, IOException {
		this.message.writeTo(_out);
	}

}
