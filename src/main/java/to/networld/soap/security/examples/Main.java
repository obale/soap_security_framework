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

package to.networld.soap.security.examples;

import java.io.FileOutputStream;
import java.security.cert.X509Certificate;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.ws.security.WSEncryptionPart;

import to.networld.soap.security.factories.SOAPSecMessageFactory;
import to.networld.soap.security.keystores.JKSKeyStore;

/**
 * @author Alex Oberhauser
 */
public class Main {
	
	private static void addContentToSOAPMessage(SOAPMessage _message) throws SOAPException {
		SOAPBody body = _message.getSOAPBody();
		SOAPElement element = body.addChildElement(new QName("ownElement"));
		element.addTextNode("Just a little bit of text for testing purpose.");
		_message.saveChanges();
	}

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		final String pwd = "v3ryS3cr3t";
		final String keystoreFile = Main.class.getResource("/keystores/keystore.jks").getFile();
		final String alias = "johndoe";
		final String pkcs12File = Main.class.getResource("/keystores/johndoe.p12").getFile();
		
		JKSKeyStore keyHandler = new JKSKeyStore(keystoreFile, pwd);
		X509Certificate certificate = keyHandler.getX509Certificate(alias);
		
		SOAPMessage message = SOAPSecMessageFactory.newInstance(certificate.getPublicKey(), 15);
		
		/*
		 * Add some content. 
		 */
		addContentToSOAPMessage(message);
		
		System.out.println("[*] newInstance(..) SOAP Message:");
		message.writeTo(System.out);
		System.out.println("\n");
		
		
        Vector<WSEncryptionPart> parts = new Vector<WSEncryptionPart>();
        WSEncryptionPart part = new WSEncryptionPart(
                "Timestamp",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                "Header");
        parts.add(part);
        part = new WSEncryptionPart(
                "Body",
                "http://schemas.xmlsoap.org/soap/envelope/",
                "");
        parts.add(part);
		
        SOAPSecMessageFactory.signSOAPMessage(message, parts, 
        		pkcs12File,
        		"johndoe", "johndoe");
        
//        SOAPSecMessageFactory.encryptSOAPMessage(message, parts, keyHandler.getKeyStore(), "rootca");
        
        SOAPSecMessageFactory.checkSecurityConstraints(message,
        		pkcs12File,
        		"johndoe", "johndoe");
        
        FileOutputStream fd = new FileOutputStream("/tmp/raw_enc_soap.xml");
		message.writeTo(fd);
		System.out.println();
	}

}
