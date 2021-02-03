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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import com.zacwolf.commons.crypto.InvalidPassphraseException;
import com.zacwolf.commons.crypto._CRYPTOfactory;
import com.zacwolf.commons.crypto.components.SupportedCipher;
import com.zacwolf.commons.crypto.components.SupportedCrypto;

/**
 * This class reads a Java crypto KeyPair parsed from a PuTTYGen created PPK file.
 */
public class KeyFileReader_PuTTY implements KeyFile{

final	static	public	String		PPKHeader		=	"PuTTY-User-Key-File-";
final	static	public	String		PPKMacMagic		=	"putty-private-key-file-mac-key";

final			private	byte[]		formattedKey;
				private	PublicKey	pubkey;
				private	PrivateKey	privkey;

				//Putty PPK specific attriute
				private	int			format			=	0;
				private	String		type			=	null;
				private	String		encryption		=	null;
				private	String		comment			=	null;
				private	String		mac				=	null;


	/**
	 *
	 * @param formattedKey
	 * @throws IOException
	 */
    public KeyFileReader_PuTTY(final byte[] formattedKey) throws IOException {
    	if (!isFormatted(formattedKey)) {
			throw new IOException("Key is not formatted in the PuTTY key format!");
		}
    	this.formattedKey	=	formattedKey;
    }


 final
 	/**
 	 *
 	 * @param formattedKey
 	 * @return
 	 */
	public static boolean isFormatted(final byte[] formattedKey) {
final	BufferedReader		reader	=	new BufferedReader(new InputStreamReader(new ByteArrayInputStream(formattedKey)));
		try {
		String				line	=	reader.readLine();
			//The first line of the file should be PPKHeader, but incase, read through any empty or white space containing lines
			while(line != null && (line.isEmpty() || !line.matches("(.*)[a-zA-Z0-9](.*)"))) {
							line	=	reader.readLine();
			}
			return line != null && line.startsWith(PPKHeader);
		} catch (final IOException ex) {
			return false;
		}
	}


@Override
final
	/**
	 * @param passphrase If the private key is encrypted, as passphrase is required to decrypt the key
	 * @return KeyPair
	 */
	public KeyPair toKeyPair(final String passphrase) throws IOException, InvalidPassphraseException{
		if (privkey!=null) {
			return new KeyPair(pubkey,privkey);
		}

final	BufferedReader		reader				=	new BufferedReader(new InputStreamReader(new ByteArrayInputStream(formattedKey)));
final	StringBuilder		publicbase64		=	new StringBuilder();
final	StringBuilder		privatebase64		=	new StringBuilder();
		try {
		String				line				=	reader.readLine();
			while(line != null && !line.trim().isEmpty()) {
							line				=	line.trim();
				if (line.startsWith(PPKHeader)) {
							format				=	line.startsWith(PPKHeader+"2:") ? 2 : 1;
							type				=	line.substring(line.indexOf(":") + 1).trim();
				}
				if (line.startsWith("Encryption:")) {
							encryption			=	line.substring(line.indexOf(":") + 1).trim();
				}
				if (line.startsWith("Comment:")) {
							comment				=	line.substring(line.indexOf(":") + 1).trim();
				}
				if (line.startsWith("Public-Lines:")) {
final	int					lines				=	Integer.parseInt(line.substring(line.indexOf(":") + 1).trim());
					for (int i = 0; i < lines; i++) {
							line				=	reader.readLine().trim();
						if (line != null) {
							publicbase64.append(line);
						} else {
							throw new IOException("Corrupt public key data in PuTTY key file");
						}
					}
				}
				if (line.startsWith("Private-Lines:")) {
final	int					lines				=	Integer.parseInt(line.substring(line.indexOf(":") + 1).trim());
					for (int i = 0; i < lines; i++) {
							line				=	reader.readLine().trim();
						if (line != null) {
							privatebase64.append(line);
						} else {
							throw new IOException("Corrupt private key data in PuTTY key file");
						}
					}
				}
				if (line.startsWith("Private-MAC:")) {
							mac					=	line.substring(line.indexOf(":")+1).trim();
				}			line				=	reader.readLine();
			}
			if (format==1) {
				throw new IOException("Putty version 1 key files [PuTTY-User-Key-File-1] are not supported at this time");
			}

final	byte[]				privblob			=	Base64.decode(privatebase64.toString());
final	byte[]				pubblob				=	Base64.decode(publicbase64.toString());
final	ByteArrayReader		pubreader			=	new ByteArrayReader(pubblob);
final	String				t					=	pubreader.readString();
			if (!type.equals(t)){
				throw new IOException("Key type:"+type+" does not match the type:"+t+" specified after PuTTY-User-Key-File-2:");
			}

			try {
				if (format>0 && type!=null && privblob.length>0 && pubblob.length>0) {
					//If encryption is set, use the passphrase to decrypt the private key
					if (encryption.equals("aes256-cbc")) {
final	SupportedCipher			cipher			=	SupportedCrypto.getInstance(encryption).cipher();
final	byte[]					iv				=	new byte[40];
final	byte[]					key				=	new byte[40];
final	DigestHelper			hash			=	new DigestHelper("SHA-1");
								hash.putInt(0);
								hash.putBytes(passphrase.getBytes());
final	byte[]					key1			=	hash.doFinal();
								hash.putInt(1);
								hash.putBytes(passphrase.getBytes());
final	byte[]					key2			=	hash.doFinal();
								System.arraycopy(key1, 0, key, 0, 20);
								System.arraycopy(key2, 0, key, 20, 20);
								cipher.init(javax.crypto.Cipher.DECRYPT_MODE, iv, key);
								cipher.transform(privblob);
					}
					/* PuTTY PPK uses a mac hash to determine if any of the key values
					 * (type/encryption/comment/publickey/privatekey) have been modified
					 * since the key file was created. This is an HmacSH1 hash, that uses
					 * a secret key that is an SH1 hash of the string PPKMacMagic+passcode
					 */
final	ByteArrayOutputStream	valToMacHash	=	new ByteArrayOutputStream();
								// PuTTY PPK uses SSH Wire encoding of String values in the format:
								// [4-byte-int{Big-Endian}-length of String][String of length bytes]

								// Encode the length of the type parm, then its value
								valToMacHash.write(ByteArrayWriter.encodeInt(type.length()));
								valToMacHash.write(type.getBytes());

								// Encode the length of the encryption parm, then its value
								valToMacHash.write(ByteArrayWriter.encodeInt(encryption.length()));
								valToMacHash.write(encryption.getBytes());

								// Encode the length of the comment parm, then its value
								valToMacHash.write(ByteArrayWriter.encodeInt(comment.length()));
								valToMacHash.write(comment.getBytes());

								// Encode the length of the pubblob, then the pubbloc
								// [which has already been Base64 decoded into a byte array]
								valToMacHash.write(ByteArrayWriter.encodeInt(pubblob.length));
								valToMacHash.write(pubblob);

								// Encode the length of the privblob, then the privblob
								// [which has already been Base64 decoded and decrypted into a byte array]
								valToMacHash.write(ByteArrayWriter.encodeInt(privblob.length));
								valToMacHash.write(privblob);

								// Create an HmacSHA1 macdigest
final	Mac						m				=	Mac.getInstance("HmacSHA1",_CRYPTOfactory.BC);
								// Specify a SecretKey that is itself an SH1 hash of the value PPKMacMagic+passphrase
								m.init(new SecretKeySpec(MessageDigest.getInstance("SHA-1",_CRYPTOfactory.BC).digest((PPKMacMagic+(encryption!=null?passphrase:"")).getBytes()), "HmacSHA1"));
final	String					mhash			=	new String(Hex.encode(m.doFinal(valToMacHash.toByteArray())));
					if (!mac.equals(mhash)){
						/* There is no "real" invalid hash exception, but the number one reason that the hash values
						 * don't match is because the passphrase used to decrypted the private key is incorrect
						 * so we're just going to assume that if encryption is specified that the hash comparison
						 * failed for this reason.
						 */
						if (encryption!=null) {
							throw new InvalidPassphraseException();
						}
						/* After decryption of the private key failing, the reason that hash values don't match
						 * is because one of the other key values (type,encryption,comment) has been modified.
						 * More than likely it's the comment. Since this is the same logic that PuTTY uses to
						 * varify a key file, then that's what we'll use as well.
						 */
						throw new IOException("This file has been altered/tampered with since it was created by PuTTYGen. WILL NOT PROCEED!");
					}

		/*
		 * Here we do the actual work of creating the Java PublicKey and PrivateKey objects, based on the
		 * type value specified in the PPK file:
		 *
		 * ssh-dss
		 * ssh-rsa
		 * ecdsa-sha2-nistp[256/384/512]
		 * ssh-ed25519
		 */
final	ByteArrayReader			privreader		=	new ByteArrayReader(privblob);
					try {
// ssh-dss
						if (type.equals("ssh-dss")) {
final	BigInteger				p				=	pubreader.readBigInteger();
final	BigInteger				q				=	pubreader.readBigInteger();
final	BigInteger				g				=	pubreader.readBigInteger();
final	BigInteger				y				=	pubreader.readBigInteger();
final	BigInteger				x				=	privreader.readBigInteger();

							if (format == 1) {
								//TODO add putty1 format handing
							}
final	KeyFactory				factory			=	SupportedCrypto.getInstance(type).keyfactory().getKeyFactory();
								pubkey			=	factory.generatePublic(new DSAPublicKeySpec(p, q, g, y));
								privkey			=	factory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));

// ssh-rsa
						} else if (type.equals("ssh-rsa")) {
final	BigInteger				publicExponent	=	pubreader.readBigInteger();
final	BigInteger				modulus			=	pubreader.readBigInteger();
final	BigInteger				privateExponent	=	privreader.readBigInteger();
final	KeyFactory				factory			=	SupportedCrypto.getInstance(type).keyfactory().getKeyFactory();
								pubkey			=	factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
								privkey			=	factory.generatePrivate(new RSAPrivateKeySpec(modulus,	privateExponent));

// ecdsa-sha2-nistp[256/384/512]
						} else if (type.startsWith("ecdsa-sha2-")) {
final		String				curve;
								switch(pubreader.readString()) {
									case "nistp521":
										curve	=	"secp521r1";
										break;
									case "nistp384":
										curve	=	"secp384r1";
										break;
									case "nistp256":
										curve	=	"secp256r1";
										break;
									default:
										throw new IOException("Unexpected EC DSA curve type:"+type);
								};
final	KeyPairGenerator		gen				=	SupportedCrypto.getInstance(type).keyfactory().getKeyPairGenerator();
								gen.initialize(new ECGenParameterSpec(curve),_CRYPTOfactory.RANDOM);
final	KeyPair					tmp				=	gen.generateKeyPair();
final	ECParameterSpec			ecspec			=	((ECPublicKey) tmp.getPublic()).getParams();
final	byte[]					bpub			=	pubreader.readBinaryString();
final	int						fieldSize		=	ecspec.getCurve().getField().getFieldSize();
final	int						len				=	(fieldSize + 7) / 8;
final	byte[]					x				=	new byte[len];
final	byte[]					y				=	new byte[len];
								System.arraycopy(bpub, 1, x, 0, len);
								System.arraycopy(bpub, len + 1, y, 0, len);
final	ECPoint					p				=	new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
final	BigInteger				s				=	privreader.readBigInteger();
final	KeyFactory				factory			=	SupportedCrypto.getInstance("ssh2-ec").keyfactory().getKeyFactory();
								pubkey			=	factory.generatePublic(new ECPublicKeySpec(p, ecspec));
								privkey			=	factory.generatePrivate(new ECPrivateKeySpec(s, ecspec));

// ssh-ed25519
						} else if (type.equals("ssh-ed25519")) {
final	byte[]					bpub			=	pubreader.readBinaryString();
final	byte[]					bpriv			=	privreader.readBinaryString();
final	KeyFactory				factory			=	SupportedCrypto.getInstance(type).keyfactory().getKeyFactory();
final	SubjectPublicKeyInfo	pubKeyInfo		=	new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), bpub);
final	X509EncodedKeySpec		x509KeySpec 	=	new X509EncodedKeySpec(pubKeyInfo.getEncoded());
								pubkey			=	factory.generatePublic(x509KeySpec);
final	PrivateKeyInfo			privKeyInfo		=	new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(bpriv));
final	PKCS8EncodedKeySpec     pkcs8KeySpec	=	new PKCS8EncodedKeySpec(privKeyInfo.getEncoded());
								privkey			=	factory.generatePrivate(pkcs8KeySpec);

/*  Code for using the alternative ed25519 net.i2p.crypto provider
 * 	    <dependency>
 *		    <groupId>net.i2p.crypto</groupId>
 *		    <artifactId>eddsa</artifactId>
 *		    <version>[0.3.0,)</version>
 *		</dependency>
 *
final	KeyPairGenerator	gen				=	KeyPairGenerator.getInstance("EdDSA", "EdDSA");
							gen.initialize(EdDSANamedCurveTable.getByName("Ed25519"),random);
final	KeyPair				tmp				=	gen.generateKeyPair();
final	EdDSAParameterSpec	spec			=	((EdDSAPublicKey) tmp.getPublic()).getParams();
final	byte[]				pk				=	pub.readBinaryString();
final	GroupElement		A				=	new GroupElement(spec.getCurve(), pk,true);
final	byte[]				s				=	priv.readBinaryString();
final	KeyFactory			factory			=	SupportedCrypto.getInstance(type).keyfactory().getKeyFactory();
							pubkey			=	factory.generatePublic(new EdDSAPublicKeySpec(A,spec));
							privkey			=	factory.generatePrivate(new EdDSAPrivateKeySpec(s,spec));
*/
						} else {
							throw new IOException("Unexpected key type "+ type);
						}
					} finally {
						privreader.close();
					}
				}
			} finally {
				pubreader.close();
			}
			return new KeyPair(pubkey,privkey);
		} catch (final Throwable ex) {
			if (ex instanceof IOException) {
				throw (IOException)ex;
			} else if (ex instanceof InvalidPassphraseException) {
				throw (InvalidPassphraseException)ex;
			}
			throw new IOException("The PuTTY key could not be read! "+ ex.getMessage());
		}
	}

}
