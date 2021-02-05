/* com.zacwolf.commons.crypto.components.SupportedCrypto.java
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

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public enum SupportedCrypto {
		RSA("ssh-rsa",SupportedKeyFactory.RSA,SupportedCipher.RSANONEPKCS1PADDING,SupportedDigest.SHA512,SupportedSignature.SHA512WITHRSAANDMGF1),
		DSA("ssh-dss",SupportedKeyFactory.DSA,null,SupportedDigest.SHA512,SupportedSignature.SHA512WITHDSA),
		ED25519("ssh-ed25519",SupportedKeyFactory.ED25519,null,SupportedDigest.SHA512,SupportedSignature.ED25519),
//		EDDSA("ssh-ed25519",SupportedKeyFactory.EDDSA,null,SupportedDigest.SHA512,SupportedSignature.EDDSA),
		AES128CBC("aes128-cbc",SupportedCipher.AES128CBCNOPADDING),
		AES128CTR("aes128-ctr",SupportedCipher.AES128CTRNOPADDING),
		AES192CBC("aes192-cbc",SupportedCipher.AES192CBCNOPADDING),
		AES192CTR("aes192-ctr",SupportedCipher.AES192CTRNOPADDING),
		AES256CBC("aes256-cbc",SupportedCipher.AES256CBCNOPADDING),
		AES256CTR("aes256-ctr",SupportedCipher.AES256CTRNOPADDING),
		BLOWFISHCBC("blowfish-cbc",SupportedCipher.BLOWFISHCBCNOPADDING),
		DESCBC("des-cbc", SupportedCipher.DESCBCNOPADDING),
		RSAPKCS1PADDING("rsa-pkcs",SupportedCipher.RSANONEPKCS1PADDING),
		TRIPPLEDESCTR("3des-ctr",SupportedCipher.TRIPPLEDESCTRNOPADDING),
		TRIPPLEDESCBC("3des-cbc",SupportedCipher.TRIPPLEDESCBCNOPADDING),
		ECDSASHA2NISTP256("ecdsa-sha2-nistp256",SupportedKeyFactory.EC,SupportedDigest.SHA256,SupportedSignature.SHA256WITHECDSA),
		ECDSASHA2NISTP384("ecdsa-sha2-nistp384",SupportedKeyFactory.EC,SupportedDigest.SHA384,SupportedSignature.SHA384WITHECDSA),
		ECDSASHA2NISTP521("ecdsa-sha2-nistp521",SupportedKeyFactory.EC,SupportedDigest.SHA512,SupportedSignature.SHA512WITHECDSA),
		;

final	public	static	Map<String,SupportedCrypto>	cryptos	=	new HashMap<String,SupportedCrypto>();
				static{
			        for (final SupportedCrypto algo : EnumSet.allOf(SupportedCrypto.class)) {
			            cryptos.put(algo.alias, algo);
			            cryptos.put(algo.name(), algo);
			        }
			    }

		String				alias;
		SupportedKeyFactory	factory;
		SupportedCipher		cipher;
		SupportedDigest		digest;
		SupportedSignature	signature;

		SupportedCrypto(final String alias, final SupportedCipher cipher, final SupportedDigest digest, final SupportedSignature signature){
			this.alias		=	alias;
			factory			=	null;
			this.cipher		=	cipher;
			this.digest		=	digest;
			this.signature	=	signature;
		}

		SupportedCrypto(final String alias, final SupportedCipher cipher){
			this.alias		=	alias;
			factory			=	null;
			this.cipher		=	cipher;
			digest			=	null;
			signature		=	null;
		}

		SupportedCrypto(final String alias, final SupportedKeyFactory factory, final SupportedCipher cipher, final SupportedDigest digest, final SupportedSignature signature){
			this.alias		=	alias;
			this.factory	=	factory;
			this.cipher		=	cipher;
			this.digest		=	digest;
			this.signature	=	signature;
		}

		SupportedCrypto(final String alias, final SupportedKeyFactory factory, final SupportedDigest digest, final SupportedSignature signature){
			this.alias		=	alias;
			this.factory	=	factory;
			cipher			=	null;
			this.digest		=	digest;
			this.signature	=	signature;
		}

		public String alias() {
			return alias;
		}

		public SupportedKeyFactory keyfactory() {
			return factory;
		}

		public SupportedCipher cipher() {
			return cipher;
		}

		public SupportedDigest digest() {
			return digest;
		}

		public SupportedSignature signature() {
			return signature;
		}

		public static boolean isValid(final String alias) {
			return cryptos.containsKey(alias);
		}

		public static SupportedCrypto getInstance(final String alias) {
			return cryptos.get(alias);
		}
}
