/* com.zacwolf.commons.crypto.io.KeyFileReader_PGP.java
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

import java.io.IOException;
import java.security.KeyPair;
import java.util.logging.Logger;

import com.zacwolf.commons.crypto.InvalidPassphraseException;

/**
 *
 */
public class KeyFileReader_PGP extends KeyFile{
final	static	private	Logger	logger;

		static {// Common static logger
								logger				=	KeyFile.LOGGER;
		}

	/**
	 * @param mac
	 * @param keypair
	 */
	public KeyFileReader_PGP(final String mac, final KeyPair keypair){
		super(mac, keypair);
	}

final

	public static KeyFile read(final byte[] keyContent, final String passphrase)   throws IOException, InvalidPassphraseException, ReaderException{
		logger.fine("ENTER:"+KeyFileReader_PGP.class.getName()+".read() [STATIC]");
		try {
		} finally {
			logger.fine("EXIT:"+KeyFileReader_PGP.class.getName()+".read() [STATIC]");
		}

		throw new ReaderException();

	}

}
