/* com.zacwolf.commons.crypto.components.SupportedDigest.java
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

import java.math.BigInteger;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import com.zacwolf.commons.crypto.components.SupportedCipher.ValueException;
import com.zacwolf.commons.crypto.io.ByteArrayWriter;

/**
 *
 */
public enum SupportedDigest implements org.bouncycastle.crypto.Digest {
		MD5("MD5"),
		SHA1("SHA-1"),
		SHA256("SHA-256"),
		SHA384("SHA-384"),
		SHA512("SHA-512"),
		HMACMD5("HmacMD5"),
		HMACSHA1("HmacSha1"),
		HMACSHA256("HmacSha256"),
		HMACSHA512("HmacSha512"),
		X509("X.509")
		;

final	static	Map<String,SupportedDigest>	digests	=	new	HashMap<String,SupportedDigest>();
		static{
	        for (final SupportedDigest digest : EnumSet.allOf(SupportedDigest.class)) {
	            digests.put(digest.alias, digest);
	        }
	    }


final	private	String			alias;
		private MessageDigest	digest	=	null;

	/**
	 *
	 */
	SupportedDigest(final String alias){
		this.alias	=	alias;
	}


	public static enum Padding{
		MGF1
	}

	public String alias() {
		return alias;
	}

	@Override
	public String toString() {
		return alias;
	}

	public byte[] doFinal() {
		return digest.digest();
	}

	public void putBigInteger(final BigInteger bi) {
final	byte[]	data	=	bi.toByteArray();
		putInt(data.length);
		putBytes(data);
	}

	public void putByte(final byte b) {
		digest.update(b);
	}

	public void putBytes(final byte[] data) {
		digest.update(data, 0, data.length);
	}

	public void putBytes(final byte[] data, final int offset, final int len) {
		digest.update(data, offset, len);
	}

	public void putInt(final int i) {
		putBytes(ByteArrayWriter.encodeInt(i));
	}

	public void putString(final String str) {
		putInt(str.length());
		putBytes(str.getBytes());
	}

	@Override
	public void reset() {
		digest.reset();
	}

	public String getProvider() {
		return digest.getProvider().getName();
	}

	@Override
	public String getAlgorithmName(){
		return digest.getAlgorithm();
	}

	@Override
	public int getDigestSize(){
		return digest.getDigestLength();
	}

	@Override
	public void update(final byte in){
		digest.update(in);
	}

	@Override
	public void update(final byte[] in, final int inOff, final int len){
		digest.update(in, inOff, len);
	}

	@Override
	public int doFinal(final byte[] out, final int outOff){
		try {
			return digest.digest(out, 0, outOff);
		} catch (final DigestException e) {
			e.printStackTrace();
		}
		return -1;
	}

	public static SupportedDigest getInstance(final String alias) throws ValueException {
		if (!digests.containsKey(alias)) {
			throw new ValueException("Not a valid digest");
		}
final	SupportedDigest	sd			=	digests.get(alias);
		try {
						sd.digest	=	MessageDigest.getInstance(sd.toString());
		} catch (final NoSuchAlgorithmException e) {
			//Won't happen since everything is hardcoded
			e.printStackTrace();
		}
		return sd;
	}

	public static boolean isValid(final String digest) {
		return digests.containsKey(digest);
	}


}
