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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Interface containing the  algorithms required by the API.

 *
 */
public enum SupportedCipher   {

		AES128CBCNOPADDING(SupportedCipher.Name.AES,SupportedCipher.Mode.CBC,SupportedCipher.Padding.NoPadding,16),
		AES128CTRNOPADDING(SupportedCipher.Name.AES,SupportedCipher.Mode.CTR,SupportedCipher.Padding.NoPadding,16),
		AES192CBCNOPADDING(SupportedCipher.Name.AES,SupportedCipher.Mode.CBC,SupportedCipher.Padding.NoPadding,24),
		AES192CTRNOPADDING(SupportedCipher.Name.AES,SupportedCipher.Mode.CTR,SupportedCipher.Padding.NoPadding,24),
		AES256CBCNOPADDING(SupportedCipher.Name.AES,SupportedCipher.Mode.CBC,SupportedCipher.Padding.NoPadding,32),
		AES256CTRNOPADDING(SupportedCipher.Name.AES,SupportedCipher.Mode.CTR,SupportedCipher.Padding.NoPadding,32),
		BLOWFISHCBCNOPADDING(SupportedCipher.Name.Blowfish,SupportedCipher.Mode.CBC,SupportedCipher.Padding.NoPadding),
		DESCBCNOPADDING(SupportedCipher.Name.DES,SupportedCipher.Mode.CBC,SupportedCipher.Padding.NoPadding),
		RSANONEPKCS1PADDING(SupportedCipher.Name.RSA,SupportedCipher.Mode.NONE,SupportedCipher.Padding.PKCS1Padding),
		TRIPPLEDESCTRNOPADDING(SupportedCipher.Name.DESede,SupportedCipher.Mode.CTR,SupportedCipher.Padding.NoPadding),
		TRIPPLEDESCBCNOPADDING(SupportedCipher.Name.DESede,SupportedCipher.Mode.CBC,SupportedCipher.Padding.NoPadding),
		;


final	private	Name	spec;
final	private	Mode	mode;
final	private	Padding	padding;
final	private	Integer	keysize;
		private	Cipher	cipher	=	null;


	SupportedCipher(final Name spec, final Mode mode, final Padding padding){
		this(spec,mode,padding,null);
	}

	SupportedCipher(final Name spec, final Mode mode, final Padding padding, final Integer keysize){
		this.spec		=	spec;
		this.mode		=	mode;
		this.padding	=	padding;
		this.keysize	=	keysize;
		try {
			cipher		=	Cipher.getInstance(spec.name()+(mode!=null?"/"+mode.name():"")+(padding!=null?"/"+padding.name():""));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}



	@Override
	public String toString() {
		return spec.name()+(mode!=null?"/"+mode.name():"")+(padding!=null?"/"+padding.name():"");
	}

	public SupportedCipher.Name spec() {
		return spec;
	}

	public String specname() {
		return spec.name();
	}

	public String mode() throws ValueException {
		if (mode==null) {
			throw new ValueException("Mode is not applicable to this cipher type");
		}
		return mode.name();
	}

	public String padding() throws ValueException {
		if (padding==null) {
			throw new ValueException("Padding is not applicable to this cipher type");
		}
		return padding.name();
	}

	public int keysize() throws ValueException {
		if (keysize==null) {
			throw new ValueException("Keysize is not applicable to this cipher type");
		}
		return keysize;
	}

	public void init(final int mode, final byte[] iv, final byte[] keydata)	throws java.io.IOException {
		try {
final	byte[]			actualKey	=	new byte[keysize];
						System.arraycopy(keydata, 0, actualKey, 0, actualKey.length);
final	SecretKeySpec	kspec		=	new SecretKeySpec(actualKey, spec.name());
						cipher.init(mode, kspec, new IvParameterSpec(iv, 0,	getBlockSize()));
		} catch (final InvalidKeyException | InvalidAlgorithmParameterException e) {
			//won't happen because values are hardcoded
		}
	}

	public KeyPair generateKeyPair(final int keySize) {
java.security.KeyPairGenerator	keyPairGenerator	=	null;
		try {					keyPairGenerator	=	java.security.KeyPairGenerator.getInstance(specname(), cipher.getProvider());
		} catch (final NoSuchAlgorithmException e) {
			//won't happen because values are hardcoded;
		}
		keyPairGenerator.initialize(keySize);
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * Transform the byte array according to the cipher mode.
	 *
	 * @param data
	 * @throws IOException
	 */
	public void transform(final byte[] data) throws IOException {
		transform(data, 0, data, 0, data.length);
	}

	public void transform(final byte[] buf, final int start, final byte[] output, final int off, final int len)	throws java.io.IOException {
		if (len > 0) {
final	byte[]	tmp		=	cipher.update(buf, start, len);
			System.arraycopy(tmp, 0, output, off, len);
		}
	}

	public String getProvider() {
		return cipher.getProvider().getName();
	}

	public int getBlockSize() {
		return cipher.getBlockSize();
	}


	public static enum Name{
		DES,
		DESede,
		IDEA,
		AES,
		Blowfish,
		Twofish,
		Threefish,
		Serpent,
		MARS,
		ElGamal,
		RSA,
		ARCFOUR,
		;

	}

	public static enum Mode{
		NONE,
		CBC,
		CCM,
		CFB,
		CTR,
		CTS,
		ECB,
		GCM,
		OFB,
		PCBC,
		;
	}

	public static enum Padding{
		NoPadding,
		ISO10126Padding,
		OAEPP,
		PKCS1Padding,
		PKCS5Padding,
		SSL3Padding,
		;
	}


	public static class ValueException  extends Exception{
final	private	static	long serialVersionUID = -1739113058377366730L;

		    /**
	     * Constructs a new exception with {@code null} as its detail message.
	     * The cause is not initialized, and may subsequently be initialized by a
	     * call to {@link #initCause}.
	     */
	    public ValueException() {
	        super();
	    }

	    /**
	     * Constructs a new exception with the specified detail message.  The
	     * cause is not initialized, and may subsequently be initialized by
	     * a call to {@link #initCause}.
	     *
	     * @param   message   the detail message. The detail message is saved for
	     *          later retrieval by the {@link #getMessage()} method.
	     */
	    public ValueException(final String message) {
	        super(message);
	    }

	    /**
	     * Constructs a new exception with the specified detail message and
	     * cause.  <p>Note that the detail message associated with
	     * {@code cause} is <i>not</i> automatically incorporated in
	     * this exception's detail message.
	     *
	     * @param  message the detail message (which is saved for later retrieval
	     *         by the {@link #getMessage()} method).
	     * @param  cause the cause (which is saved for later retrieval by the
	     *         {@link #getCause()} method).  (A <tt>null</tt> value is
	     *         permitted, and indicates that the cause is nonexistent or
	     *         unknown.)
	     * @since  1.4
	     */
	    public ValueException(final String message, final Throwable cause) {
	        super(message, cause);
	    }

	    /**
	     * Constructs a new exception with the specified cause and a detail
	     * message of <tt>(cause==null ? null : cause.toString())</tt> (which
	     * typically contains the class and detail message of <tt>cause</tt>).
	     * This constructor is useful for exceptions that are little more than
	     * wrappers for other throwables
	     *
	     */
	    public ValueException(final Throwable cause) {
	        super(cause);
	    }

	    /**
	     * Constructs a new exception with the specified detail message,
	     * cause, suppression enabled or disabled, and writable stack
	     * trace enabled or disabled.
	     *
	     * @param  message the detail message.
	     * @param cause the cause.  (A {@code null} value is permitted,
	     * and indicates that the cause is nonexistent or unknown.)
	     * @param enableSuppression whether or not suppression is enabled
	     *                          or disabled
	     * @param writableStackTrace whether or not the stack trace should
	     *                           be writable
	     * @since 1.7
	     */
	    protected ValueException(final String message, final Throwable cause,
	                        final boolean enableSuppression,
	                        final boolean writableStackTrace) {
	        super(message, cause, enableSuppression, writableStackTrace);
	    }
	}
}
