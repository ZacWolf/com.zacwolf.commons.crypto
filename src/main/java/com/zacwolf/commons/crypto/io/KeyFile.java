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

import java.io.IOException;
import java.security.KeyPair;

import com.zacwolf.commons.crypto.InvalidPassphraseException;


/**
 *
 */
/**
 * Interface which all private key formats must implement to provide decoding
 * and decryption of the private key into a suitable format for the API.
 *
 * Based on original work by:
 * @author Lee David Painter
 */
public interface KeyFile {

	/**
	 * Convienice method to support conversion back to original JCE
	 *
	 * @return the key pair stored in this private key file.
	 * @throws IOException
	 */
	public KeyPair toKeyPair(final String passphrase) throws IOException, InvalidPassphraseException;

}