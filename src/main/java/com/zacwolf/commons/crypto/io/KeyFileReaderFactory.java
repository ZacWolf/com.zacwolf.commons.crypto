/* com.zacwolf.commons.crypto.keyfileio.KeyReaderFactory.java
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;


/**
 *
 */
public class KeyFileReaderFactory {

final	public	static	int		OPENSSH_FORMAT	=	0;
final	public	static	int		PPK_FORMAT		=	1;

final
	/**
	 * Parse formatted data and return a suitable KeyFile implementation.
	 *
	 * @param formattedkey
	 * @return KeyFile
	 * @throws IOException
	 */
	public static KeyFile parse(final byte[] formattedkey) throws IOException {
		try {
			if (KeyFileReader_PuTTY.isFormatted(formattedkey)) {
				return new KeyFileReader_PuTTY(formattedkey);
			} else {
				throw new IOException("A suitable key format could not be found!");
			}
		} catch (final OutOfMemoryError ex) {
			throw new IOException(
					"An error occurred parsing a private key file! Is the file corrupt?");
		}

	}

final
	/**
	 * Parse a File object and return a suitable KeyFile implementation
	 *
	 * @param keyfile
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public static KeyFile parse(final File keyfile) throws FileNotFoundException, IOException {
		return parse(new FileInputStream(keyfile));
	}

final
	/**
	 * Parse an InputStream and return a suitable KeyFile implementation.
	 *
	 * @param in
	 * @return KeyFile
	 * @throws IOException
	 */
	public static KeyFile parse(final InputStream in) throws IOException {
		try {
final	ByteArrayOutputStream	out = new ByteArrayOutputStream();
		int						read;
			while ((read = in.read()) > -1) {
								out.write(read);
			}
			return parse(out.toByteArray());
		} finally {
			try {				in.close();
			} catch (final IOException ex) {
			}
		}
	}


}

