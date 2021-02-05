/* com.zacwolf.commons.crypto.components.SupportedKeyFactory.java
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
package com.zacwolf.commons.crypto.components;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import com.zacwolf.commons.crypto._CRYPTOfactory;



/**
 *
 */
public enum SupportedKeyFactory {
	DH("DiffieHellman"),
	DSA("DSA"),
	RSA("RSA"),
	RSASSAPSS("RSASSA-PSS"),
	EC("EC"),
	ED25519("Ed25519"),
//	EDDSA("EdDSA",_CRYPTOfactory.EdDSA),
	;

final	String		value;
final	Provider	provider;

	SupportedKeyFactory(final String value){
		this.value		=	value;
		provider		=	_CRYPTOfactory.PROVIDER;
	}

	SupportedKeyFactory(final String value, final Provider provider){
		this.value		=	value;
		this.provider	=	provider;
	}

	public String value() {
		return value;
	}

	public KeyFactory getKeyFactory() {
		try {
			return KeyFactory.getInstance(value,provider);
		} catch (final NoSuchAlgorithmException e) {
			//Won't happen because values are hard-coded
			e.printStackTrace();
			return null;
		}
	}

	public KeyPairGenerator getKeyPairGenerator() {
		try {
			return KeyPairGenerator.getInstance(value,provider);
		} catch (final NoSuchAlgorithmException e) {
			//Won't happen because values are hard-coded
			e.printStackTrace();
			return null;
		}
	}
}
