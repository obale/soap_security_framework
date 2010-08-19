package to.networld.soap.security.interfaces;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
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
	 * @param _keystore A JKS Keystore that includes the public key that is needed for the encryption.
	 * @param _alias The alias of the receiver.
	 * @throws SOAPException
	 * @throws CredentialException
	 * @throws IOException
	 */
	public void encryptSOAPMessage(Vector<WSEncryptionPart> _encryptionParts, KeyStore _keystore, String _alias) 
		throws SOAPException, CredentialException, IOException;
		
	/**
	 * Method for the signing of a SOAP message.
	 * 
	 * @param _signingParts The parts of the message that should be signed.
	 * @param _pkcs12File The file path to a p12 of the agent that signs the message.
	 * @param _alias The alias of the agent.
	 * @param _password The password to be able to access the private key.
	 * @throws SOAPException 
	 * @throws IOException 
	 * @throws CredentialException 
	 */
	public void signSOAPMessage(Vector<WSEncryptionPart> _signingParts, String _pkcs12File, String _alias, String _password) 
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
	public Vector<?> checkSecurityConstraints(String _pkcs12File, String _alias, String _password, KeyStore _keystore)
		throws SOAPException, CredentialException, IOException;
}
