/* com.zacwolf.commons.crypto.DuplicateEntryException.java
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
package com.zacwolf.commons.crypto;

/**
 *
 */
public class DuplicateEntryException extends Exception{

	/**
	 *
	 */
	private static final long serialVersionUID = -8556452701190679921L;

	/**
	 *
	 */
	public DuplicateEntryException(){}

	/**
	 * @param alias
	 */
	public DuplicateEntryException(final String alias){
		super("A KeyStore Entry already exists for alias:"+alias);
	}

	/**
	 * @param cause
	 */
	public DuplicateEntryException(final Throwable cause){
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public DuplicateEntryException(final String message, final Throwable cause){
		super(message, cause);
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public DuplicateEntryException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace){
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
