/* com.zacwolf.commons.crypto._CRYPTOfactory.java
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.zacwolf.commons.crypto.components.SupportedCipher;
import com.zacwolf.commons.crypto.components.SupportedCrypto;
import com.zacwolf.commons.crypto.components.SupportedDigest;
import com.zacwolf.commons.crypto.io.KeyFile;
import com.zacwolf.commons.crypto.io.KeyFileReaderFactory;

/**
 *
 */
public class _CRYPTOfactory{
//final			static	DefaultAlgorithmNameFinder	nameFinder		=	new DefaultAlgorithmNameFinder();
final	public	static	Provider					BC				=	new BouncyCastleProvider();
//final	public	static	Provider					EdDSA			=	new EdDSASecurityProvider();
		public	static	SecureRandom				RANDOM;
final	private	static	Logger						logger			=	LogManager.getLogger(_CRYPTOfactory.class.getName());

		private	static enum KEYSTOREDEFAULTS{
			TYPE("PKCS12"),
			FILENAME("keystore.p12"),
			CRYPTOSPEC(SupportedCrypto.RSA),
			ROOTALIAS("ROOT"),
			KEYSIZE(4096)
			;

			private Object value;
			private KEYSTOREDEFAULTS(final Object value) {
				this.value	=	value;
			}

			public Object value() {
				return value;
			}

			@Override
			public String toString() {
				return value.toString();
			}
		}

		static {
			Security.addProvider(BC);
//			Security.addProvider(EdDSA);
			Security.setProperty("crypto.policy", "unlimited");
			try {
				RANDOM	=	SecureRandom.getInstanceStrong();
			} catch (final NoSuchAlgorithmException e) {
				//won't happen because this is a system provided instance
			}
		}

final	private	static	int							MAXACTIVE		=	Runtime.getRuntime().availableProcessors();
		private	static	int							activecrypts	=	0;

final	private			File						keyStoreFile;
final	private			KeyStore					keyStore;
final	private			PasswordProtection			keyStorePASS;
final	private			KeyPair						keyStoreRootKeyPair;
final	private			Certificate					keyStoreRootCA;


	/**
	 * This method allows you to instantiate the CRYPTOfactory without a File object, only a KeyStore.
	 * This means that you are responsible for saving the keystore object outside of this class.
	 *
	 * @param keyStore
	 * @param keyStorePass
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws CertificateException
	 */
	public _CRYPTOfactory(final KeyStore keyStore, final String keyStorePass) throws KeyStoreException,NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException{
		this(null,keyStore,keyStorePass,KEYSTOREDEFAULTS.ROOTALIAS.toString());
	}

	/**
	 * This method allows you to instantiate the CRYPTOfactory without a File object, only a KeyStore.
	 * This means that you are responsible for saving the keystore object outside of this class.
	 * This method also allow you to specify the alias used to load the root keypair and root certificate with is required by this class.
	 *
	 * @param keyStore
	 * @param keyStorePass
	 * @param keyStoreRootAlias
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws CertificateException
	 */
	public _CRYPTOfactory(final KeyStore keyStore, final String keyStorePass, final String keyStoreRootAlias) throws KeyStoreException,NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException{
		this(null,keyStore,keyStorePass,keyStoreRootAlias);
	}

	/**
	 * @param keyStoreFile
	 * @param keyStore
	 * @param keyStorePass
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws CertificateException
	 */
	public _CRYPTOfactory(final File keyStoreFile, final KeyStore keyStore, final String keyStorePass) throws KeyStoreException,NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException{
		this(keyStoreFile,keyStore,keyStorePass,KEYSTOREDEFAULTS.ROOTALIAS.toString());
	}

	public _CRYPTOfactory(final File keyStoreFile, final KeyStore keyStore, final String keyStorePass, final String keyStoreRootAlias) throws KeyStoreException,NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException{
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+" CONSTRUCTOR");
		try {				this.keyStoreFile			=	keyStoreFile;
			if (this.keyStoreFile==null) {
				logger.warn("A null keyStoreFile reference means you must save any changes to the KeyStore object outside of this class.");
			}
							this.keyStore				=	keyStore;
							keyStorePASS				=	new PasswordProtection(keyStorePass.toCharArray());
		Key					privKey						=	null;
			try {			privKey						=	keyStore.getKey(keyStoreRootAlias, keyStorePass.toCharArray());
			} catch (final UnrecoverableKeyException e1) {
				throw new KeyStoreException("Incorrect Password");
			}
			if (privKey==null || !(privKey instanceof PrivateKey)) {
final	SupportedCrypto				sc					=	(SupportedCrypto)KEYSTOREDEFAULTS.CRYPTOSPEC.value();
		logger.error("The KeyStore you provided does not contain a root PrivateKey/Certificate, which is required for all further operations.\n"+
					  "The following will be generated and added to the KeyStore via alias:"+keyStoreRootAlias+"\n"+
					  "A PrivateKey of type  "+sc.name()+"\n"+
					  "A SelfSigned rootCA signed with "+ sc.signature().toString()+" that expires in 5 years.");
final	KeyPair						keyPair				=	new KeyPairGenerator(sc.cipher()).generate((int)KEYSTOREDEFAULTS.KEYSIZE.value());
									keyStoreRootCA		=	generateSelfSignedCert(keyPair);
			} else {				keyStoreRootCA		=	keyStore.getCertificate(keyStoreRootAlias);
			}
			keyStoreRootKeyPair	=	new KeyPair(keyStoreRootCA.getPublicKey(), (PrivateKey) privKey);
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+" CONSTRUCTOR");
		}
	}

final
	/**
	 * @param alias
	 * @param k
	 * @param password
	 * @throws KeyStoreException
	 */
	void addSecretKey(final String alias, final SecretKey k, final String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		try {
			addSecretKey(alias,k,password,true);
		} catch (final DuplicateEntryException e) {
			//wont happen because overwrite is set to true
		}
	}


final
	/**
	 * @param alias
	 * @param k
	 * @param password
	 * @param overwrite
	 * @throws KeyStoreException
	 * @throws DuplicateEntryException
	 */
	void addSecretKey(final String alias, final SecretKey k, final String password, final boolean overwrite) throws KeyStoreException, DuplicateEntryException, NoSuchAlgorithmException, CertificateException, IOException {
		if (!overwrite && keyStore.containsAlias(alias)) {
			throw new DuplicateEntryException(alias);
		}
		keyStore.setKeyEntry(alias, k, password!=null && password.length()>0?password.toCharArray():keyStorePASS.getPassword(), null);
		writeKeyStore();
	}

final
	/**
	 * @param alias
	 * @param k
	 * @param password
	 * @param chain
	 * @throws KeyStoreException
	 */
	void addPrivateKey(final String alias, final PrivateKey k, final String password, final Certificate[] chain) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		try {
			addPrivateKey(alias,k,password,chain,true);
		} catch (final DuplicateEntryException e) {
			//wont happen because overwrite is set to true
		}
	}


final
	/**
	 * @param alias
	 * @param k
	 * @param password
	 * @param chain
	 * @param overwrite
	 * @throws KeyStoreException
	 * @throws DuplicateEntryException
	 */
	void addPrivateKey(final String alias, final PrivateKey k, final String password, final Certificate[] chain,final boolean overwrite) throws KeyStoreException, DuplicateEntryException, NoSuchAlgorithmException, CertificateException, IOException {
		if (!overwrite && keyStore.containsAlias(alias)) {
			throw new DuplicateEntryException(alias);
		}
		keyStore.setKeyEntry(alias.toUpperCase(), k, password!=null && password.length()>0?password.toCharArray():keyStorePASS.getPassword(), chain);
		writeKeyStore();
	}


final
	/**
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	void writeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".writeKeyStore()");
		try {
			if (keyStoreFile==null) {
				logger.error("KEYSTORE NOT SAVED: A call was made to save the keystore, but the keyStoreFile param is null.\n"+
							 "You'll need to manually save the changes to your KeyStore object!");
			} else {
final	FileOutputStream	out							=	new FileOutputStream(keyStoreFile);
				try { 			keyStore.store(out, keyStorePASS.getPassword());
				} finally {		out.close();
				}
			}
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".writeKeyStore()");
		}
	}

final
	/**
	 * Since crypt operations are very CPU intensive, we keep the number
	 * of threads actually doing crypt operations to a max number
	 */
	void ready(){
		while (activecrypts>MAXACTIVE) {
			try {
				Thread.sleep(500);
			} catch (final InterruptedException e) {
				// If interrupted (shutting down), drop out of waiting
			}
		}
	}



final

	static File createTempFile(final String name, final String extension) throws IOException{
final	File	file	=	File.createTempFile(name, extension);
				file.deleteOnExit();
		return file;
	}

final
	/**
	 * Generates a Self Signed Certificated based on the keypair and Signature type passed in.
	 *
	 * @param keyPair the public/private KeyPair used to generate and sign the certificate
	 * @param ss SupportedSignature algorithim used to sign the certificate
	 * @return
	 */
	static Certificate generateSelfSignedCert(final KeyPair keyPair) throws OperatorCreationException, CertIOException, CertificateException {
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".generateSelfSignedCert() [STATIC]");
		try {
final	Instant						now					=	Instant.now();
final	Date						notBefore			=	Date.from(now);
final	Date						notAfter			=	Date.from(now.plus(Duration.ofDays(5*365)));//Default to a 5year certificate
final	SupportedCrypto				crypto				=	SupportedCrypto.valueOf(keyPair.getPrivate().getAlgorithm().toUpperCase());
final	SupportedDigest				digest				=	crypto.digest();//spec.getDefaultDigest();
final	ContentSigner				contentSigner		=	new JcaContentSignerBuilder(crypto.signature().toString()).build(keyPair.getPrivate());
final	X500Name					issuer				=	new X500Name("CN=rootCA");
final	DigestCalculator			digestCal			=	new BcDigestCalculatorProvider().get(new DefaultDigestAlgorithmIdentifierFinder().find(digest.name()));
final	X509v3CertificateBuilder	certificateBuilder	=	new JcaX509v3CertificateBuilder(
																issuer,
															    BigInteger.valueOf(now.toEpochMilli()),
														        notBefore,
														        notAfter,
														        issuer,
														        keyPair.getPublic()
														     )
		        .addExtension(Extension.subjectKeyIdentifier, false, new X509ExtensionUtils(digestCal).createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())))
		        .addExtension(Extension.authorityKeyIdentifier, false, new X509ExtensionUtils(digestCal).createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())))
		        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

			return new JcaX509CertificateConverter().setProvider(BC).getCertificate(certificateBuilder.build(contentSigner));

//		} catch (final ValueException e ) {
//			//won't happen because values are hardedcoded
//			return null;
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".generateSelfSignedCert() [STATIC]");
		}
	}

final
	/**
	 * @param pubkey_toSign
	 * @param pubkey_cn
	 * @param expiresInDays
	 * @return
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws CertificateException
	 */
	public	X509Certificate signPublicKey(final PublicKey pubkey_toSign, final X500Name pubkey_cn, final int expiresInDays) throws OperatorCreationException, CertIOException, CertificateException {
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".signPublicKey()");
		try {
final	Instant						now					=	Instant.now();
final	Date						notBefore			=	Date.from(now);
final	Date						notAfter			=	Date.from(now.plus(Duration.ofDays(expiresInDays)));
final	SupportedCrypto				crypto				=	SupportedCrypto.valueOf(keyStoreRootKeyPair.getPrivate().getAlgorithm());
final	SupportedDigest				digest				=	crypto.digest();
final	ContentSigner				contentSigner		=	new JcaContentSignerBuilder(crypto.signature().toString()).build(keyStoreRootKeyPair.getPrivate());
final	DigestCalculator			digestCal			=	new BcDigestCalculatorProvider().get(new DefaultDigestAlgorithmIdentifierFinder().find(digest.name()));
final	X509v3CertificateBuilder	certificateBuilder	=	new JcaX509v3CertificateBuilder(
																new X500Name ("CN="+((X509Certificate)keyStoreRootCA).getIssuerX500Principal().getName()),
															    BigInteger.valueOf(now.toEpochMilli()),
														        notBefore,
														        notAfter,
														        pubkey_cn,
														        pubkey_toSign
														     )
		        .addExtension(Extension.subjectKeyIdentifier, false, new X509ExtensionUtils(digestCal).createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubkey_toSign.getEncoded())))
		        .addExtension(Extension.authorityKeyIdentifier, false, new X509ExtensionUtils(digestCal).createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyStoreRootKeyPair.getPublic().getEncoded())))
		        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			return new JcaX509CertificateConverter().setProvider(BC).getCertificate(certificateBuilder.build(contentSigner));
//		} catch (final ValueException e) {
//			//won't happen because values are hardcoded
//			return null;
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".signPublicKey()");
		}
	}

final

	public void addTrustedPublicKey(final String alias, final X500Name cn, final PublicKey k, final String password, final int expiresInDays) throws KeyStoreException, DuplicateEntryException, OperatorCreationException, CertIOException, CertificateException {
		addTrustedPublicKey(alias,cn,k,password,expiresInDays,true);
	}


final
	/**
	 * @param alias
	 * @param cn
	 * @param k
	 * @param password
	 * @param expiresInDays
	 * @param overwrite
	 * @throws KeyStoreException
	 * @throws DuplicateEntryException
	 * @throws OperatorCreationException
	 * @throws CertIOException
	 * @throws CertificateException
	 */
	public void addTrustedPublicKey(final String alias, final X500Name cn, final PublicKey k, final String password, final int expiresInDays, final boolean overwrite) throws KeyStoreException, DuplicateEntryException, OperatorCreationException, CertIOException, CertificateException {
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".addTrustedPublicKey()");
		try {
			if (!overwrite && keyStore.containsAlias(alias)) {
				throw new DuplicateEntryException(alias);
			}
			keyStore.setKeyEntry(alias.toUpperCase(), k,
								 password!=null && password.length()>0?password.toCharArray():keyStorePASS.getPassword(),
								 new Certificate[] {signPublicKey(k, cn, expiresInDays)}
								 );
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".addTrustedPublicKey()");
		}
	}


final
	/**
	 * Dump the providers/ciphers
	 */
	public static void dumpCiphers(){
        for (final Provider provider : Security.getProviders()) {
            for (final Provider.Service service : provider.getServices()) {
                //if ("Cipher".equals(service.getType())) {
                    System.out.println(String.format("provider:%s,  type:%s,  algorithm:%s", service.getProvider(), service.getType(), service.getAlgorithm()));
                //}
            }
        }
	}


final
	/**
	 * Generate a new KeyStore file/object based on the default keystore type, and default root alias.
	 *
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @param keyFile
	 * @param keyFilePassword
	 * @param expiresInDays
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws OperatorCreationException
	 */
	public static KeyStore createNewKeyStore(final	File			keyStoreFile,
											 final	String			keyStorePassword,
											 final	File			keyFile,
											 final String			keyFilePassword,
											 final	int				expiresInDays
											) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
		return createNewKeyStore(keyStoreFile,keyStorePassword,null,keyFile,keyFilePassword,expiresInDays);
	}


final
	/**
	 * Generate a new KeyStore file/object
	 *
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @param keyStoreRootAlias
	 * @param keyFile
	 * @param keyFilePassword
	 * @param expiresInDays
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws OperatorCreationException
	 */
	public static KeyStore createNewKeyStore(final	File			keyStoreFile,
											 final	String			keyStorePassword,
											 final	String			keyStoreRootAlias,
											 final	File			keyFile,
											 final	String			keyFilePassword,
											 final	int				expiresInDays
											) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
		return createNewKeyStoreFile(null,keyStoreFile,keyStorePassword,null,keyFile,keyFilePassword,expiresInDays);
	}

final
	/**
	 * @param keyStoreType
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @param keyFile
	 * @param keyFilePassword
	 * @param expiresInDays
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws OperatorCreationException
	 */
	public static KeyStore createNewKeyStore(final	String			keyStoreType,
											 final	File			keyStoreFile,
											 final	String			keyStorePassword,
											 final	File			keyFile,
											 final	String			keyFilePassword,
											 final	int				expiresInDays
											) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
		return createNewKeyStoreFile(keyStoreType,keyStoreFile,keyStorePassword,null,keyFile,keyFilePassword,expiresInDays);
	}


final
	/**
	 * @param keyStoreType
	 * @param keyStoreFile
	 * @param keyStorePassword
	 * @param keyStoreRootAlias
	 * @param keyFile
	 * @param keyFilePassword
	 * @param expiresInDays
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws OperatorCreationException
	 */
	public static KeyStore createNewKeyStoreFile(	String			keyStoreType,
											 final	File			keyStoreFile,
											 final	String			keyStorePassword,
											 		String			keyStoreRootAlias,
											 final	File			keyFile,
											 		String			keyFilePassword,
											 final	int				expiresInDays
											) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
		if (keyStoreFile==null) {
			throw new KeyStoreException("keyStoreFile can not be null");
		}
		if (keyStoreFile.exists()) {
			throw new IOException("KeyStore:"+keyStoreFile.getAbsolutePath()+" already exists!");
		}
		if (keyFile==null || !keyFile.exists()) {
			throw new IOException("Key file does not exist");
		}
		if (keyStoreRootAlias==null) {
									keyStoreRootAlias	=	KEYSTOREDEFAULTS.ROOTALIAS.toString();
		}
		if (keyStoreType==null) {
			keyStoreType		=	KEYSTOREDEFAULTS.TYPE.toString();
		}
		if (keyFilePassword==null) {
									keyFilePassword		=	keyStorePassword;
		}
final	KeyPair						keyPair				=	getKeyPairFromFile(keyFile,keyFilePassword);
final	Certificate[]				chain				=	new Certificate[]{generateSelfSignedCert(keyPair)};
		return createNewKeyStoreFile(keyStoreType, keyStoreFile,keyStorePassword,keyStoreRootAlias,keyPair.getPrivate(),chain);
	}

	final

	public static KeyStore createNewKeyStoreFile(final	String			keyStoreType,
												 final	File			keyStoreFile,
												 final	String			keyStorePassword,
												 		String			keyStoreRootAlias,
												 final	PrivateKey		keyStoreRootPrivateKey,
												 final Certificate[]	keyStoreRootChain
												) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if (keyStoreFile==null) {
			throw new KeyStoreException("keyStoreFile can not be null");
		}
		if (keyStoreFile.exists()) {
			throw new KeyStoreException("KeyStore:"+keyStoreFile.getAbsolutePath()+" already exists!");
		}
		if (keyStoreRootAlias==null) {
			keyStoreRootAlias	=	KEYSTOREDEFAULTS.TYPE.toString();
		}
		if (keyStoreRootPrivateKey==null || keyStoreRootChain==null) {
			throw new KeyStoreException("You must provide a ROOT PrivateKey and a Certificate chain to create a new KeyStore with this method");
		}
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".createNewKeyStore()  [STATIC]");
		try {
final	KeyStore			ks			=	KeyStore.getInstance(keyStoreType,BC);
							ks.load(null, keyStorePassword.toCharArray());
							ks.setKeyEntry(keyStoreRootAlias, keyStoreRootPrivateKey, keyStorePassword.toCharArray(), keyStoreRootChain);
final	FileOutputStream	out			=	new FileOutputStream(keyStoreFile);
			try { 			ks.store(out, keyStorePassword.toCharArray());
			} finally {		out.close();
			}
			return ks;
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".createNewKeyStore() [STATIC]");
		}
	}



final
	/**
	 * @param keyfile
	 * @param keypassword
	 * @return
	 * @throws IOException
	 */
	public static KeyPair getKeyPairFromFile(final File keyfile, final String keypassword) throws IOException {
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".getKeyPairFromFile() [STATIC]");
		try {
final	KeyFile	keyFile	=	KeyFileReaderFactory.parse(keyfile);
			try {
				return keyFile.toKeyPair(keypassword);
			} catch (final InvalidPassphraseException e) {
				throw new IOException(e);
			}
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".getKeyPairFromFile() [STATIC]");
		}
	}


final
	/**
	 * @param filein
	 * @param password
	 * @return
	 * @throws IOException
	 */
	public static KeyPair getKeyPairFromInputStream(final InputStream filein, final String password) throws IOException {
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".getKeyPairFromInputStream() [STATIC]");
final	KeyFile	keyFile		=	KeyFileReaderFactory.parse(filein);
		try {
			return keyFile.toKeyPair(password);
		} catch (final InvalidPassphraseException e) {
			throw new IOException(e);
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".getKeyPairFromInputStream() [STATIC]");
		}
	}


final
	/**
	 *
	 */
	public static class KeyPairGenerator{
final	SupportedCipher	sc;

		/**
		 * @param sc
		 */
		public KeyPairGenerator(final SupportedCipher sc) {
			this.sc	=	sc;
		}

		/**
		 * @param keySize
		 * @return
		 */
		public KeyPair generate(final int keySize) {
java.security.KeyPairGenerator	keyPairGenerator	=	null;
			try {				keyPairGenerator	=	java.security.KeyPairGenerator.getInstance(sc.specname(), BouncyCastleProvider.PROVIDER_NAME);
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				//won't happen because values are hardcoded;
			}
								keyPairGenerator.initialize(keySize);
			return keyPairGenerator.generateKeyPair();
		}

	}


final
	/**
	 * @param args
	 */
	public static void main(final String[] args){
		logger.debug("ENTER:"+_CRYPTOfactory.class.getName()+".main()");
		try {
final	Options				options			= new Options();
							options.addOption("dc", "dumpciphers", false, "Dump all the various cryptography ciphers present in this jvm.")
									.addOption("ks", "keystore-file", true, "KeyStore file name")
									.addOption(Option.builder("ksp")
												.desc("KeyStore password")
												.longOpt("keystore-pass")
												.hasArg()
												.numberOfArgs(1)
												.required()
												.build()
									)
									.addOption("ksa", "keystore-alias", false, "Provide the keystore alias to work with")
									.addOption(Option.builder("kst")
												.desc("KeyStore type, otherwise defaults to:"+KEYSTOREDEFAULTS.TYPE.toString())
												.longOpt("keystore-type")
												.numberOfArgs(1)
												.optionalArg(true)
												.build()
									)
									.addOption(Option.builder("o")
												.desc("If the provided alias exists in the KeyStore, overwrite it.")
												.longOpt("overwrite")
												.numberOfArgs(0)
												.optionalArg(true)
												.build()
									)
									.addOption("k", "key-file", true, "Load key file name")
									.addOption(Option.builder("kp")
												.desc("Key password. If not provided the KeyStore password will be used.")
												.longOpt("key-pass")
												.numberOfArgs(1)
												.optionalArg(true)
												.build()
									)
									;
final	CommandLineParser		parser			=	new DefaultParser();
		CommandLine				cmd				=	null;
			try {				cmd				=	parser.parse(options, args);

				if (cmd.hasOption("dc")) {//DUMP CIPHERS
					_CRYPTOfactory.dumpCiphers();
				}

				if (!cmd.hasOption("ksp")) { //KeyStore password must be provided
					throw new Exception("No KeyStore password was provided, can not proceed");
				}
final	File					ksFile			=	new File(cmd.hasOption("ks")?cmd.getOptionValue("ks"):KEYSTOREDEFAULTS.FILENAME.toString());
final	String					ksPass			=	cmd.getOptionValue("ksp");
final	String					ksAlias			=	cmd.hasOption("ksa")?cmd.getOptionValue("ksa"):KEYSTOREDEFAULTS.ROOTALIAS.toString();
final	String					ksType			=	cmd.hasOption("kst")?cmd.getOptionValue("kst"):KEYSTOREDEFAULTS.TYPE.toString();
		KeyStore				ks				=	null;
				if (!ksFile.exists() && cmd.hasOption("k") && cmd.hasOption("kp")) {
final	File					kFile			=	new File(cmd.getOptionValue("k"));
final	String					kPass			=	cmd.getOptionValue("kp");
								ks				=	createNewKeyStore(ksFile,ksPass,kFile,kPass,365+5);
				} else {		ks				=	KeyStore.getInstance(ksType,BC);
final	FileInputStream			ksin			=	new FileInputStream(ksFile);
					try { 		ks.load(ksin, ksPass.toCharArray());
					} finally {	ksin.close();
					}
				}

		//Instantiate the _CRYPTOfactory
final	_CRYPTOfactory			cf				=	new _CRYPTOfactory(ksFile, ks, ksPass, ksAlias);


			} catch (ParseException | NullPointerException e) {
	final	HelpFormatter		formatter		=	new HelpFormatter();
	      						formatter.printHelp("_CRYPTOfactory", options);
			} catch (final Exception e) {
				e.printStackTrace();
			}
		} finally {
			logger.debug("EXIT:"+_CRYPTOfactory.class.getName()+".main()");
		}
	}
}
