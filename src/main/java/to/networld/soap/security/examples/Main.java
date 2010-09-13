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

//import java.net.URL;
import java.util.ArrayList;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
//import javax.xml.soap.SOAPConnection;
//import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngineResult;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import to.networld.soap.security.common.Credential;
import to.networld.soap.security.interfaces.ICredential;
import to.networld.soap.security.interfaces.ISecSOAPMessage;
import to.networld.soap.security.security.SOAPSecMessageFactory;

/**
 * @author Alex Oberhauser
 */
public class Main {
	
	private static void addContentToSOAPMessage(SOAPMessage _message) throws SOAPException {
		SOAPBody body = _message.getSOAPBody();
		SOAPElement secElement = body.addChildElement(new QName("secureSubTree"));
		SOAPElement element = secElement.addChildElement(new QName("ownElement"));
		element.addTextNode("This is a very secret message and should be encrypted ;)");
		_message.saveChanges();
	}
	
	private static void printDecryptedText(Vector<?> _secVector) {
		for ( Object entry : _secVector ) {
			if ( entry instanceof WSSecurityEngineResult ) {
				try {
					WSSecurityEngineResult secEntry = (WSSecurityEngineResult)entry;
					ArrayList<?> arrayList = (ArrayList<?>)secEntry.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
					for ( Object obj : arrayList ) {
						WSDataRef data = (WSDataRef) obj;
						NodeList nodeList = data.getProtectedElement().getChildNodes();
						System.out.println(data.getName());
						for ( int count=0; count < nodeList.getLength(); count++ ) { 
							Node node = nodeList.item(count);
							System.out.print(node.getNodeName() + ": ");
							System.out.println(node.getTextContent());
						}
						System.out.println("---");
					}
				} catch (Exception e)  {
					System.out.println(e.getLocalizedMessage());
				}
			} else {
				System.out.println(entry.getClass());
			}
		}
	}

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		final String keystoreFile = Main.class.getResource("/keystores/keystore.jks").getFile();
		final String pwd = "v3ryS3cr3t";
		final String pkcs12FileJohn = Main.class.getResource("/keystores/johndoe.p12").getFile();
		final String pkcs12FileRoot = Main.class.getResource("/keystores/rootca.p12").getFile();
		
		ICredential johnCredential = new Credential(pkcs12FileJohn, "johndoe", "johndoe", keystoreFile, pwd);
		ICredential rootCredential = new Credential(pkcs12FileRoot, "rootca", "rootca", keystoreFile, pwd);
		
		ISecSOAPMessage message = SOAPSecMessageFactory.newInstance(0);
		
		/*
		 * Add some content. 
		 */
		addContentToSOAPMessage(message.getSOAPMessage());
		
		System.out.println("[*] newInstance(..) SOAP Message:");
		message.printSOAPMessage(System.out);
		System.out.println("\n");
		
        Vector<WSEncryptionPart> parts = new Vector<WSEncryptionPart>();
        WSEncryptionPart part = new WSEncryptionPart(
                "Timestamp",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                "");
        parts.add(part);
        WSEncryptionPart part1 = new WSEncryptionPart(
                "secureSubTree",
                "",
                "");
        parts.add(part1);
		
        message.signSOAPMessage(parts, rootCredential); 
        		
        message.encryptSOAPMessage(parts, rootCredential, "johndoe");
        
        System.out.println("[*] Secure SOAP Message:");
		message.printSOAPMessage(System.out);
		System.out.println("\n");
		
//		SOAPConnectionFactory conFactory = SOAPConnectionFactory.newInstance();
//		SOAPConnection con = conFactory.createConnection();
//
//		SOAPMessage response = con.call(message.getSOAPMessage(), new URL("http://127.0.0.1:2121"));
//		System.out.println(response);
//		con.close();
        
		System.out.println("[*] Security Result Vector returned by checkSecurityConstraints(..):");
		Vector<?> secVector = message.checkSecurityConstraints(johnCredential);
		printDecryptedText(secVector);
		
		message.printSOAPMessage(System.out);
	}

}
