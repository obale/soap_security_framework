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

package to.networld.soap.security.interfaces;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Vector;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.components.crypto.CredentialException;

import to.networld.soap.security.security.SOAPSecMessageFactory;

/**
 * Interface that wraps the message with a security layer
 * and useful methods to handle security related features.<p/>
 * 
 * To gain a concrete object call {@link SOAPSecMessageFactory#newInstance(int)}
 * 
 * @author Alex Oberhauser
 */
public interface ISecSOAPMessage {
	
	public SOAPMessage getSOAPMessage();
	
	/**
	 * Write the message to the given output stream.
	 * 
	 * @param os The output stream where to write the message.
	 * @throws SOAPException
	 * @throws IOException
	 */
	public void printSOAPMessage(OutputStream out)
		throws SOAPException, IOException;
	
	/**
	 * Method for the encryption of a SOAP message.
	 * 
	 * @param _encryptionParts The parts of the message that should be encrypted.
	 * @param _credential Credentail that includes a JKS Keystore that includes the public key that is needed for the encryption.
	 * @param _alias The alias of the receiver.
	 * @throws SOAPException
	 * @throws CredentialException
	 * @throws IOException
	 */
	public void encryptSOAPMessage(Vector<WSEncryptionPart> _encryptionParts, ICredential _credential, String _alias) 
		throws SOAPException, CredentialException, IOException;
		
	/**
	 * Method for the signing of a SOAP message.
	 * 
	 * @param _signingParts The parts of the message that should be signed.
	 * @param _credential The credential of the current user.
	 * @throws SOAPException 
	 * @throws IOException 
	 * @throws CredentialException 
	 */
	public void signSOAPMessage(Vector<WSEncryptionPart> _signingParts, ICredential _credential) 
		throws SOAPException, CredentialException, IOException;
	
	/**
	 * Checks the security constraints. First decrypt (TODO), than signature check.
	 * 
	 * @param _pkcs12File The file path to a p12 of the agent.
	 * @param _alias The alias of the agent.
	 * @param _password The password to be able to access the private key.
	 * @return The 
	 * @throws SOAPException 
	 * @throws IOException 
	 * @throws CredentialException 
	 */
	public Vector<?> checkSecurityConstraints(ICredential _credential)
		throws SOAPException, CredentialException, IOException;
}
