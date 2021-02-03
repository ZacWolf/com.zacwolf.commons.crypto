/* com.zacwolf.commons.crypto.components.SupportSignature.java
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

/**
 *
 */
public enum SupportedSignature {

	//MD5WITHRSA("MD5WithRSA",SupportedDigest.MD5,null),
	EDDSA(SupportedSignature.Type.EdDSA),
	ED25519(SupportedSignature.Type.Ed25519),
	SHA1WITHDSA(SupportedSignature.Type.DSA,SupportedDigest.SHA1),
	SHA1WITHRSA(SupportedSignature.Type.RSA,SupportedDigest.SHA1),
	SHA1WITHRSAANDMGF1(SupportedSignature.Type.RSA,SupportedDigest.SHA1,SupportedDigest.Padding.MGF1),
	SHA256WITHDSA(SupportedSignature.Type.DSA,SupportedDigest.SHA256),
	SHA256WITHRSA(SupportedSignature.Type.RSA,SupportedDigest.SHA256),
	SHA256WITHRSAANDMGF1(SupportedSignature.Type.RSA,SupportedDigest.SHA256,SupportedDigest.Padding.MGF1),
	SHA256WITHECDSA(SupportedSignature.Type.ECDSA,SupportedDigest.SHA256),
	SHA384WITHDSA(SupportedSignature.Type.DSA,SupportedDigest.SHA512),
	SHA384WITHRSA(SupportedSignature.Type.RSA,SupportedDigest.SHA384),
	SHA384WITHRSAANDMGF1(SupportedSignature.Type.RSA,SupportedDigest.SHA384,SupportedDigest.Padding.MGF1),
	SHA384WITHECDSA(SupportedSignature.Type.ECDSA,SupportedDigest.SHA384),
	SHA512WITHDSA(SupportedSignature.Type.DSA,SupportedDigest.SHA512),
	SHA512WITHRSA(SupportedSignature.Type.RSA,SupportedDigest.SHA512),
	SHA512WITHRSAANDMGF1(SupportedSignature.Type.RSA,SupportedDigest.SHA512,SupportedDigest.Padding.MGF1),
	SHA512WITHECDSA(SupportedSignature.Type.ECDSA,SupportedDigest.SHA512),
	;

final	private	Type					type;
final	private	SupportedDigest			digest;
final	private	SupportedDigest.Padding	padding;



	SupportedSignature(final Type type){
		this.type		=	type;
		digest			=	null;
		padding			=	null;
	}

	SupportedSignature(final Type type, final SupportedDigest digest){
		this.type		=	type;
		this.digest		=	digest;
		padding			=	null;
	}

	SupportedSignature(final Type type, final SupportedDigest digest, final SupportedDigest.Padding padding){
		this.type		=	type;
		this.digest		=	digest;
		this.padding	=	padding;
	}



	@Override
	public String toString() {
		return digest==null?type.name():digest.name()+"With"+type.name()+(padding!=null?"And"+padding:"");
	}

	public SupportedDigest digest() {
		return digest;
	}

	public String padding() {
		return padding==null?"":padding.name();
	}


	public static enum Type{
		RSA,
		DSA,
		ECDSA,
		EdDSA,
		Ed25519,
		;
	}
}
