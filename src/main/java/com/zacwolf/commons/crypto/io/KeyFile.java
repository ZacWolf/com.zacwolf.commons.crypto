/* com.zacwolf.commons.crypto.KeyFile.java
 *
 * Copyright (C) 2021 Zac Morris <a href="mailto:zac@zacwolf.com">zac@zacwolf.com</a>

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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.logging.Logger;

import com.zacwolf.commons.crypto.InvalidPassphraseException;


/**
 * Factory class to determine the proper key reader and writer.
 *
 */
public class KeyFile  {
final	static	public	Logger	LOGGER	=	Logger.getLogger(KeyFile.class.getName());
final			private	KeyPair	keypair;

	protected KeyFile(final String mac,final KeyPair keypair){
		this.keypair	=	keypair;
	}

	public KeyPair getKeyPair() {
		return keypair;
	}

	public static KeyFile readContent(final File file, final String passphrase) throws IOException, InvalidPassphraseException {
		if (!file.exists() || !file.isFile()) {
			throw new IOException("File:"+file.getCanonicalPath()+" does not exist or is not a file object");
		}
final	byte[]				keyContent	=	Files.readAllBytes(file.toPath());
		String				ext			=	file.getName();
		if (!ext.contains(".")) {
			return readContent(keyContent,passphrase);
		}
							ext			=	ext.substring(ext.lastIndexOf("."));
		try {//attempt matching reader by filename
			switch(ext) {
				case".ppk":
					LOGGER.fine("KeyFile.readContent(): "+ext+" file detected, trying KeyFileReader_PuTTY");
					return KeyFileReader_PuTTY.read(keyContent,passphrase);
				case".pem":
				case".ssl":
					LOGGER.fine("KeyFile.readContent(): "+ext+" file detected, trying KeyFileReader_OPENSSL");
					return KeyFileReader_OPENSSL.read(keyContent,passphrase);
				case".key":
				case".pgp":
					LOGGER.fine("KeyFile.readContent(): "+ext+" file detected, trying KeyFileReader_PGP");
					return KeyFileReader_PGP.read(keyContent,passphrase);
			}
		} catch (final ReaderException ee) {}

		//Determine reader by file extension failed, so try by full parse
		return readContent(keyContent,passphrase);
	}

	public static KeyFile readContent(final InputStream in, final String passphrase) throws IOException, InvalidPassphraseException {
		return readContent(org.apache.commons.io.IOUtils.toByteArray(in),passphrase);
	}

	public static KeyFile readContent(final byte[] keyContent, final String passphrase) throws IOException, InvalidPassphraseException {
		try {//First try OpenSSL keyfile reader
			LOGGER.fine("KeyFile.readContent(): Trying reader:"+KeyFileReader_OPENSSL.class.getName());
			return KeyFileReader_OPENSSL.read(keyContent,passphrase);
		} catch (final ReaderException e) {
			try {//Second try the PuTTY keyfile reader
				LOGGER.fine("KeyFile.readContent(): Reader:"+KeyFileReader_OPENSSL.class.getName()+" failed, trying reader:"+KeyFileReader_PuTTY.class.getName());
				return KeyFileReader_PuTTY.read(keyContent,passphrase);
			} catch (final ReaderException ee) {
				try {//Third try the PGP keyfile reader
					LOGGER.fine("KeyFile.readContent(): Reader:"+KeyFileReader_PuTTY.class.getName()+" failed, trying reader:"+KeyFileReader_PGP.class.getName());
					return KeyFileReader_PuTTY.read(keyContent,passphrase);
				} catch (final ReaderException eee) {
					LOGGER.severe("Could not find a reader for this key type");
					throw new IOException("Could not find a reader for this key type");
				}
			}
		}
	}

	public static class ReaderException extends Exception{
		private static final long serialVersionUID = -7138791139430383352L;

		/**
		 *
		 */
		public ReaderException(){}

		/**
		 * @param alias
		 */
		public ReaderException(final String alias){
			super("A KeyStore Entry already exists for alias:"+alias);
		}

		/**
		 * @param cause
		 */
		public ReaderException(final Throwable cause){
			super(cause);
		}

		/**
		 * @param message
		 * @param cause
		 */
		public ReaderException(final String message, final Throwable cause){
			super(message, cause);
		}

		/**
		 * @param message
		 * @param cause
		 * @param enableSuppression
		 * @param writableStackTrace
		 */
		public ReaderException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace){
			super(message, cause, enableSuppression, writableStackTrace);
		}
	}
}