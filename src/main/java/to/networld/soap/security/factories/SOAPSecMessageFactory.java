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

package to.networld.soap.security.factories;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Properties;
import java.util.UUID;
import java.util.Vector;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;

import to.networld.soap.security.common.DateHandler;

/**
 * @author Alex Oberhauser
 */
public abstract class SOAPSecMessageFactory {
	private static final WSSecurityEngine secEngine = new WSSecurityEngine();
	
	/**
	 * Creates a SOAP message with basic security constraints.
	 * 
	 * @param _certificate The X.509 certificate that is used for authentication.
	 * @return The generated SOAP message.
	 * @throws SOAPException
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws CredentialException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 */
	public static SOAPMessage newInstance(PublicKey _certificate, int _expiresInMinutes) throws SOAPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, CredentialException, IOException, CertificateException, KeyStoreException {
	    SOAPMessage soapMessage = MessageFactory.newInstance().createMessage();
	    SOAPPart soapPart = soapMessage.getSOAPPart();
	    SOAPBody soapBody = soapMessage.getSOAPBody();
	    SOAPHeader soapHeader = soapMessage.getSOAPHeader();
	    
	    SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
        soapEnvelope.addNamespaceDeclaration("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        soapEnvelope.addNamespaceDeclaration("SOAP-SEC", "http://schemas.xmlsoap.org/soap/security/2000-12");
        
        soapMessage.setProperty(SOAPMessage.WRITE_XML_DECLARATION, "false"); 
        
        /*
         * Header Part
         */
        soapHeader.addNamespaceDeclaration("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        SOAPElement secElement = soapHeader.addChildElement(soapHeader.createQName("Security", "wsse"));
        secElement.addAttribute(soapEnvelope.createQName("mustUnderstand", soapEnvelope.getPrefix()), "1");
        
//        SOAPElement binarySecElement = secElement.addChildElement(soapHeader.createQName("BinarySecurityToken",
//        		"wsse"));
//        binarySecElement.addAttribute(new QName("EncodingType"),
//        		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
//        binarySecElement.addAttribute(new QName("ValueType"), 
//        		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
//        binarySecElement.addAttribute(soapEnvelope.createQName("mustUnderstand", soapEnvelope.getPrefix()), "1");;
//        binarySecElement.addTextNode(Base64.encode(_certificate.getEncoded()));
        
        SOAPElement timestampElement = secElement.addChildElement(soapEnvelope.createQName("Timestamp", "wsu"));
        timestampElement.addAttribute(soapEnvelope.createQName("Id", "wsu"), UUID.randomUUID().toString());
        
        Calendar currentDate = Calendar.getInstance();
        timestampElement.addChildElement(soapEnvelope.createQName("Created", "wsu")).addTextNode(DateHandler.getDateString(currentDate, 0));
        timestampElement.addChildElement(soapEnvelope.createQName("Expires", "wsu")).addTextNode(DateHandler.getDateString(currentDate, _expiresInMinutes));
        timestampElement.addAttribute(soapEnvelope.createQName("id", "SOAP-SEC"), "Timestamp");
        
        /*
         * Body Part
         */
        soapBody.addAttribute(soapEnvelope.createQName("Id", "wsu"), UUID.randomUUID().toString());
        soapBody.addAttribute(soapEnvelope.createQName("id", "SOAP-SEC"), "Body");
        
        soapMessage.saveChanges();
	    return soapMessage;
	}
	
	/**
	 * Method for the encryption of a SOAP message.
	 * 
	 * @param _soapMessage The message to encrypt.
	 * @param _encryptionParts The parts of the message that should be encrypted.
	 * @param _keystore A JKS Keystore that includes the public key that is needed for the encryption.
	 * @param _alias The alias of the receiver.
	 * @throws SOAPException
	 * @throws CredentialException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 */
	public static void encryptSOAPMessage(SOAPMessage _soapMessage, Vector<WSEncryptionPart> _encryptionParts, KeyStore _keystore, String _alias) throws SOAPException, CredentialException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
		SOAPEnvelope soapEnvelope = _soapMessage.getSOAPPart().getEnvelope();
		
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
		
		_soapMessage.saveChanges();
	}
	
	/**
	 * TODO
	 * 
	 * @param _soapMessage
	 * @return
	 */
	public static SOAPMessage decryptSOAPMessage(SOAPMessage _soapMessage) {
		return _soapMessage;
	}
	
	/**
	 * Method for the signing of a SOAP message.
	 * 
	 * @param _soapMessage The message to sign.
	 * @param _signingParts The parts of the message that should be signed.
	 * @param _pkcs12File The file path to a p12 of the agent that signs the message.
	 * @param _alias The alias of the agent.
	 * @param _password The password to be able to access the private key.
	 * @throws SOAPException
	 * @throws CredentialException
	 * @throws IOException
	 */
	public static void signSOAPMessage(SOAPMessage _soapMessage, Vector<WSEncryptionPart> _signingParts, String _pkcs12File, String _alias, String _password) throws SOAPException, CredentialException, IOException {
		SOAPEnvelope soapEnvelope = _soapMessage.getSOAPPart().getEnvelope();

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
        
		_soapMessage.saveChanges();
	}
	
	@SuppressWarnings("unchecked")
	public static void checkSecurityConstraints(SOAPMessage _soapMessage, String _pkcs12File, String _alias, String _password) throws CredentialException, IOException, SOAPException {
		Document doc = _soapMessage.getSOAPPart().getEnvelope().getOwnerDocument();
		
		Properties prop = new Properties();
		prop.put("org.apache.ws.security.crypto.merlin.file", _pkcs12File);
		prop.put("org.apache.ws.security.crypto.merlin.keystore.type", "PKCS12");
		prop.put("org.apache.ws.security.crypto.merlin.keystore.password", _password);

	    Merlin crypto = new Merlin(prop);
		
		Vector resultVector = secEngine.processSecurityHeader(doc, null, null, crypto);
		for ( Object obj : resultVector ) {
			if ( obj instanceof WSSecurityEngineResult ) {
				WSSecurityEngineResult entry = (WSSecurityEngineResult)obj;
				System.out.println(entry);
			}
		}
	}
}
