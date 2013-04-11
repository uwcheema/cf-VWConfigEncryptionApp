package com.vw.common;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ObjectInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;


public class ConfigurationController extends AbstractController {

	private PublicKey encryptionKey=null;
    private Resource configResource;

    private Resource key;
    private Cipher cipher=null;
    private String message;

    public void setKey(Resource key) throws Exception {
        this.key=key;

        encryptionKey = (PublicKey) new ObjectInputStream(this.key.getInputStream()).readObject();

        cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
    }

    public void setConfigResource(Resource res) throws Exception {
        configResource = res;
        message = IOUtils.toString(configResource.getInputStream());
    }


    int i=0;

    @Override
	protected ModelAndView handleRequestInternal(HttpServletRequest request,
			HttpServletResponse response) throws Exception {

        ModelAndView model = new ModelAndView("configuration");

		String cipherText = encrypt(message, encryptionKey);
		
		model.addObject("msg", cipherText);
		return model;
	}
	
	private synchronized String encrypt(String plaintext, PublicKey publicKey) throws Exception
	{
        byte[] bytes = plaintext.getBytes("UTF-8");

		byte[] encrypted = blockCipher(bytes, Cipher.ENCRYPT_MODE);

		char[] encryptedTranspherable = Hex.encodeHex(encrypted);
		return new String(encryptedTranspherable);
	}

	private byte[] blockCipher(byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		byte[] scrambled = new byte[0];

		// toReturn will hold the total result
		byte[] toReturn = new byte[0];
		// if we encrypt we use 100 byte long blocks. Decryption requires 128
		// byte long blocks (because of RSA)
		int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

		// another buffer. this one will hold the bytes that have to be modified
		// in this step
		byte[] buffer = new byte[length];

		for (int i = 0; i < bytes.length; i++)
		{

			// if we filled our buffer array we have our block ready for de- or
			// encryption
			if ((i > 0) && (i % length == 0))
			{
				// execute the operation
				scrambled = cipher.doFinal(buffer);
				// add the result to our total result.
				toReturn = append(toReturn, scrambled);
				// here we calculate the length of the next buffer required
				int newlength = length;

				// if newlength would be longer than remaining bytes in the
				// bytes array we shorten it.
				if (i + length > bytes.length)
				{
					newlength = bytes.length - i;
				}
				// clean the buffer array
				buffer = new byte[newlength];
			}
			// copy byte into our buffer.
			buffer[i % length] = bytes[i];
		}

		// this step is needed if we had a trailing buffer. should only happen
		// when encrypting.
		// example: we encrypt 110 bytes. 100 bytes per run means we "forgot"
		// the last 10 bytes. they are in the buffer
		// array
		scrambled = cipher.doFinal(buffer);

		// final step before we can return the modified data.
		toReturn = append(toReturn, scrambled);

		return toReturn;
	}

	private byte[] append(byte[] prefix, byte[] suffix)
	{
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for (int i = 0; i < prefix.length; i++)
		{
			toReturn[i] = prefix[i];
		}
		for (int i = 0; i < suffix.length; i++)
		{
			toReturn[i + prefix.length] = suffix[i];
		}
		return toReturn;
	}

}