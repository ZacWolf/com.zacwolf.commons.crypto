/*
 * com.zacwolf.commons.crypto.keyfileio.PuTTYKeyFileReader.java
 *
 * Copyright (C) 2021 Zac Morris <a href="mailto:zac@zacwolf.com">zac@zacwolf.com</a>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * This code also leverages lessons learned from:
 *
 * The PuTTY C++ source code along with help from one of the PuTTY devs
 * Simon Tatham [https://www.chiark.greenend.org.uk/~sgtatham/]
 *
 * The PHP phpseclib3 library by Jim Wigginton <terrafrost@php.net>.
 *
 * As well as source code from the the Java j2ssh-maveric codebase[LGPL v3]:
 * [https://github.com/sshtools/j2ssh-maverick]
 */
package com.zacwolf.commons.crypto.io;

import java.math.BigInteger;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.zacwolf.commons.crypto._CRYPTOfactory;

/**
 *	Helper class that abstracts writting different data types to a digest
 */
public class DigestHelper implements org.bouncycastle.crypto.Digest {

final			MessageDigest digest;

	public DigestHelper(final String algorithm) throws NoSuchAlgorithmException {
		digest = MessageDigest.getInstance(algorithm,_CRYPTOfactory.BC);
	}

	public String getProvider() {
		return digest.getProvider().getName();
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

}
