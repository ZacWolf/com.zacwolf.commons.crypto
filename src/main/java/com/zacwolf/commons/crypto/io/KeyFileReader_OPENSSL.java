/* com.zacwolf.commons.crypto.io.KeyFileReader_OPENSSL.java
 *
 * Copyright (C) 2021-2021 Zac Morris <a href="mailto:zac@zacwolf.com">zac@zacwolf.com</a>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.zacwolf.commons.crypto.io;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PasswordException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;

import com.zacwolf.commons.crypto.InvalidPassphraseException;
import com.zacwolf.commons.crypto._CRYPTOfactory;

/**
 *
 */
public class KeyFileReader_OPENSSL extends KeyFile{

final	static	protected	String				PEM_BOUNDARY	=	"-----";
final	static	protected	String				PEM_BEGIN		=	PEM_BOUNDARY + "BEGIN ";
final	static	protected	String				PEM_END			=	PEM_BOUNDARY + "END ";
final	static	private		Logger				logger;

	static {// Common static logger
												logger			=	KeyFile.LOGGER;
	}

	/**
	 * @param mac
	 * @param keypair
	 */
	private KeyFileReader_OPENSSL(final String mac, final KeyPair keypair){
		super(mac, keypair);
	}


	private static KeyPair toKeyPair(final byte[] keyContent, final String passphrase) throws IOException, InvalidPassphraseException{
		logger.fine("ENTER:"+KeyFileReader_OPENSSL.class.getName()+".toKeyPair() [PRIVATE]");
		try {
final	BufferedReader			reader		=	new BufferedReader(new InputStreamReader(new ByteArrayInputStream(keyContent)));
final	PEMParser				pemParser	=	new PEMParser(reader);
final	Object					object		=	pemParser.readObject();
final	PEMDecryptorProvider	decProv		=	new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
final	JcaPEMKeyConverter		converter	=	new JcaPEMKeyConverter().setProvider(_CRYPTOfactory.PROVIDER);
     	KeyPair					kp;
		    if (object instanceof PEMEncryptedKeyPair) {
		        				kp			=	converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
		    } else {			kp			=	converter.getKeyPair((PEMKeyPair) object);
		    }
		    return kp;
		} catch (final PasswordException pe) {
			logger.severe("ERROR:"+KeyFileReader_OPENSSL.class.getName()+".toKeyPair() [PRIVATE] Invalid password provided");
			throw new InvalidPassphraseException(pe);
		} catch (final Exception e) {
			logger.severe("ERROR:"+KeyFileReader_OPENSSL.class.getName()+".toKeyPair() [PRIVATE] Cannot read private key:"+e.getMessage());
			throw new IOException("Cannot read private key", e);
		} finally {
			logger.fine("EXIT:"+KeyFileReader_OPENSSL.class.getName()+".toKeyPair() [PRIVATE]");
		}
	}

final
 	/**
 	 *
 	 * @param formattedKey
 	 * @return
 	 */
	public static KeyFile read(final byte[] keyContent, final String passphrase) throws IOException, ReaderException, InvalidPassphraseException {
		logger.fine("ENTER:"+KeyFileReader_OPENSSL.class.getName()+".read() [STATIC]");
		try {
		Boolean				isMyType	=	false;
final	BufferedReader		reader		=	new BufferedReader(new InputStreamReader(new ByteArrayInputStream(keyContent)));
			try {
		String				line		=	reader.readLine();
			//The first line of the file should be PPKHeader, but incase, read through any empty or white space containing lines
				while(line != null && (line.isEmpty() || !line.matches("(.*)[a-zA-Z0-9](.*)"))) {
							line		=	reader.readLine();
				}
							isMyType	=	line != null && line.startsWith(PEM_BEGIN);
			} finally {
				reader.close();
			}
			if (!isMyType) {
				throw new KeyFile.ReaderException("Not a PEM encoded File");
			}
		String				mac			=	null;
			try{			mac			=	new String(Hex.encode(MessageDigest.getInstance("SHA-1",_CRYPTOfactory.PROVIDER).digest(keyContent)));
				logger.fine("Mac calculated for file:"+mac);
			} catch ( final NoSuchAlgorithmException e) {
				//hardcoded value so won't happen;
			}
			return new KeyFile(mac,toKeyPair(keyContent,passphrase));
		} finally {
			logger.fine("EXIT:"+KeyFileReader_OPENSSL.class.getName()+".read() [STATIC]");
		}
	}

}
