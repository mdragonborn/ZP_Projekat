package implementation;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import code.GuiException;
import gui.Constants;
import gui.GuiInterfaceV1;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

public class MyCode extends CodeV3 {
	
	private final String keystore_file = "local_keystore.p12"; 
	private final String keystore_pass = "qwe123";
	private PKCS10CertificationRequest currentCsr = null;
	private KeyStore keyStore;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	@Override
	public boolean canSign(String arg0) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(arg0);
			if(cert.getKeyUsage()!=null && cert.getKeyUsage()[5])
				return true;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override //file, keypairname, algorithm
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(arg1);
			
			ExtensionsGenerator extensionsGen = new ExtensionsGenerator();
			X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
			X500Principal subject = cert.getSubjectX500Principal();
			ContentSigner signGen = new JcaContentSignerBuilder(cert.getSigAlgName()).build((PrivateKey)keyStore.getKey(arg1, keystore_pass.toCharArray()));
			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, cert.getPublicKey());
			builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGen.generate());
			
			PKCS10CertificationRequest csr = builder.build(signGen);
			
			JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(new File(arg0)));
			writer.writeObject(csr);
			writer.close();
			return true;
		} catch (KeyStoreException | CertificateEncodingException | UnrecoverableKeyException | OperatorCreationException | NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override // file, keypair, encoding, format
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
		try (FileOutputStream os = new FileOutputStream(arg0)){
			if(!keyStore.containsAlias(arg1)) {
				GuiInterfaceV1.reportError("Key doesn't exist.");
				return false;
			}
			java.security.cert.Certificate cert = keyStore.getCertificate(arg1);
			if (arg2 == gui.Constants.PEM) {
				OutputStreamWriter osWriter = new OutputStreamWriter(os);
				JcaPEMWriter writer = new JcaPEMWriter(osWriter);
				if (arg3 == 0) {
					writer.writeObject(cert);
				}
				else {
					java.security.cert.Certificate[] chain = keyStore.getCertificateChain(arg1);
					for (java.security.cert.Certificate c : chain) {
                        writer.writeObject(new PemObject("CERTIFICATE", c.getEncoded()));
                    }
				}
				writer.close();
				osWriter.close();
			}
			else {
				DataOutputStream datastream = new DataOutputStream(os);
				datastream.write(cert.getEncoded());
				datastream.close();
			}
		} catch (IOException | KeyStoreException | CertificateEncodingException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		try (FileOutputStream os = new FileOutputStream(arg1)){
			Key key = keyStore.getKey(arg0, keystore_pass.toCharArray());
			java.security.cert.Certificate[] chain = keyStore.getCertificateChain(arg0);
			
			KeyStore ks12 = KeyStore.getInstance("PKCS12");
			ks12.load(null, null);
			
			ks12.setKeyEntry(arg0, key, arg2.toCharArray(), chain);
			
			ks12.store(os, arg2.toCharArray());
						
			return true;
			
		} catch (IOException | KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String arg0) {
		try
		{
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(arg0);
			return certificate.getPublicKey().getAlgorithm();
		}catch (Exception e) {
			e.printStackTrace();
		}
		return null;
		
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		try {
			return Integer.toString(((RSAKey)(keyStore.getCertificate(arg0).getPublicKey())).getModulus().bitLength());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getSubjectInfo(String arg0) {
		try  {
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(arg0);
			JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
			return holder.getSubject().toString();
		} catch (CertificateEncodingException | KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override //file, keypair
	public boolean importCAReply(String arg0, String arg1) {
		try (FileInputStream is = new FileInputStream(arg0)) {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(arg1);
			if (cert == null) {
				access.reportError("Certificate not found");
				return false;
			}
			
			PrivateKey pk = (PrivateKey) keyStore.getKey(arg1,  keystore_pass.toCharArray());
			CMSSignedData signed = new CMSSignedData(is);
			
			List<SignerInformation> signers = new ArrayList<SignerInformation>(signed.getSignerInfos().getSigners());
	        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());

			for(SignerInformation s: signers) {
				Collection<X509CertificateHolder> signerHolder = signed.getCertificates().getMatches((Selector<X509CertificateHolder>)s.getSID());
				if(!signerHolder.stream().findFirst().isPresent()) {
					access.reportError("Reply invalid.");
					return false;
				}
				
				X509Certificate currentCert = certConverter.getCertificate(signerHolder.stream().findFirst().get());
				if(!s.verify(new JcaSimpleSignerInfoVerifierBuilder().build(currentCert))) {
					access.reportError("Reply invalid.");
					return false;
				}
			}
			
			X509CertificateHolder first = signed.getCertificates().getMatches(null)
					.stream().findFirst().get();
			X509Certificate firstCert = certConverter.getCertificate(first);
			
			if(!cert.getSubjectX500Principal().equals(firstCert.getSubjectX500Principal())) {
				access.reportError("Reply invalid.");
				return false;
			}
			
			
		} catch (KeyStoreException | IOException | UnrecoverableKeyException | NoSuchAlgorithmException | CMSException | CertificateException | OperatorCreationException e) {
			e.printStackTrace();
			return false;
		}
		
		try (FileInputStream is = new FileInputStream(arg0); FileOutputStream os = new FileOutputStream(keystore_file)) {
			Collection<?> chain = CertificateFactory.getInstance("X.509").generateCertificates(is);
			Key key = keyStore.getKey(arg1, keystore_pass.toCharArray());
			java.security.cert.Certificate[] certChain = chain.toArray(new java.security.cert.Certificate[chain.size()]);
			keyStore.setKeyEntry(arg1, key, keystore_pass.toCharArray(), certChain);
			keyStore.store(os, keystore_pass.toCharArray());
		}catch(Exception e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}

	@Override
	public String importCSR(String arg0) {
		try (FileInputStream is = new FileInputStream(new File(arg0))) {
			InputStreamReader reader = new InputStreamReader(is);
			PEMParser pr = new PEMParser(reader);
			
			currentCsr = (PKCS10CertificationRequest)pr.readObject();
			
			ContentVerifierProvider provider = new JcaContentVerifierProviderBuilder().build(currentCsr.getSubjectPublicKeyInfo());
			if(!currentCsr.isSignatureValid(provider)) {
				currentCsr = null;
				GuiV3.reportError("Not verified");
				return null;
			}
			

			String alg = null;
			switch(currentCsr.getSignatureAlgorithm().getAlgorithm().toString()) {
			case "1.2.840.113549.1.1.5":
				alg = "SHA1withRSA"; break;
			case "1.2.840.113549.1.1.11":
				alg = "SHA256withRSA"; break;
			case "1.2.840.113549.1.1.12":
				alg = "SHA384withRSA"; break;
			case "1.2.840.113549.1.1.13":
				alg = "SHA512withRSA"; break;
			default:
				return null;
			}
			
			return currentCsr.getSubject().toString()+",SA=" + alg;
			
		} catch (IOException | PKCSException | OperatorCreationException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean importCertificate(String arg0, String arg1) {
		try (FileInputStream is = new FileInputStream(arg0); FileOutputStream os = new FileOutputStream(keystore_file)){
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			List<X509Certificate> list = new ArrayList<X509Certificate>();
			while(is.available() > 0) {
				list.add((X509Certificate) certFactory.generateCertificate(is));
			}
			keyStore.setCertificateEntry(arg1, list.get(0));
			keyStore.store(os, keystore_pass.toCharArray());
		} catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
		File file = new File(arg1);

        if(!file.exists()) {
            return false;
        }

		
		try (FileInputStream is = new FileInputStream(file); FileOutputStream os = new FileOutputStream(this.keystore_file)){
						
			KeyStore ks12 = KeyStore.getInstance("PKCS12");
			ks12.load(is, arg2.toCharArray());
			Key key = ks12.getKey(arg0, arg2.toCharArray());
			
			java.security.cert.Certificate cert = ks12.getCertificate(arg0);
			this.keyStore.setKeyEntry(arg0, key, keystore_pass.toCharArray(), new X509Certificate[] {(X509Certificate) cert});
			
			keyStore.store(os, keystore_pass.toCharArray());
			
			return true;
		} catch(Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public int loadKeypair(String arg0) {
		X509Certificate cert = null;
		int ret = 0;
		try {
			cert = (X509Certificate) this.keyStore.getCertificate(arg0);
			if(cert.getKeyUsage() != null){
				if(cert.getKeyUsage()[5] == true)
					ret = 2;
				}
				else {
					try {
						// PROVERI
						cert.verify(cert.getPublicKey(), new BouncyCastleProvider());
						ret = 0;
					} catch(Exception e) {
						ret = 1;
					}
				}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return -1;
		}
		
		JcaX509CertificateHolder h;
		try {
			h = new JcaX509CertificateHolder(cert);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			return -1;
		}
		
		access.setSubject(h.getSubject().toString());
		access.setIssuer(h.getIssuer().toString());
		access.setSerialNumber(cert.getSerialNumber().toString());
		access.setNotAfter(cert.getNotAfter());
		access.setNotBefore(cert.getNotBefore());
		access.setPublicKeyAlgorithm(cert.getSigAlgName());
		access.setVersion(2);
		
		// TODO Show extensions
		Set<String> critSet = cert.getCriticalExtensionOIDs();

		if (critSet != null && !critSet.isEmpty()) {
			for (String oid : critSet) {
				
				// TODO Inhibit any policy
				if (oid.equals("2.5.29.54")) {
					access.setCritical(Constants.IAP, true);
					cert.getExtensionValue(oid);
				}
				
				if(oid.equals("2.5.29.15")) {
					access.setKeyUsage(cert.getKeyUsage());
				}
				
				if(oid.equals("2.5.29.17")) {
					try {
						StringBuilder builder = new StringBuilder();
						Collection<List<?>> subjectAlternativeNames = cert.getSubjectAlternativeNames();
						for(List name: subjectAlternativeNames) {
							builder.append(name.get(1));
							builder.append(",");
						}
						builder.delete(builder.length()-1, builder.length());
						access.setAlternativeName(Constants.SAN, builder.toString());
						access.setCritical(Constants.SAN, true);
					} catch (CertificateParsingException e) {
						e.printStackTrace();
					}
				}
			}
		}
		
		return ret;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		File file = new File(this.keystore_file);
		
		if(!file.exists()) {
			try {
				keyStore.load(null, this.keystore_pass.toCharArray());
				FileOutputStream os = new FileOutputStream(this.keystore_file);
				keyStore.store(os, this.keystore_pass.toCharArray());
				os.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	    FileInputStream fis = null;
	    try {
	        fis = new java.io.FileInputStream(this.keystore_file);
	        keyStore.load(fis, this.keystore_pass.toCharArray());
	    }
	    catch(java.io.EOFException e) {
	    	try {
				keyStore.load(null, this.keystore_pass.toCharArray());
			} catch (NoSuchAlgorithmException | CertificateException | IOException e1) {
				e1.printStackTrace();
			}
	    }
	    catch (Exception e) {
			e.printStackTrace();
		} 
	    finally {
	        try {
				fis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
	    }
	    
	    try {
			return keyStore.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	    
	    return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		try (FileOutputStream os = new FileOutputStream(new File(this.keystore_file))){
			if(keyStore.containsAlias(arg0)) {
				keyStore.deleteEntry(arg0);
				keyStore.store(os, this.keystore_pass.toCharArray());
				return true;
			}
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e1) {
			e1.printStackTrace();
		}
		
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		
			ks.load(null, this.keystore_pass.toCharArray());
			FileOutputStream os = new FileOutputStream(this.keystore_file);
			ks.store(os, this.keystore_pass.toCharArray());
			keyStore = ks;
			
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean saveKeypair(String arg0) {
		Integer keySize = Integer.valueOf(access.getPublicKeyParameter());
		KeyPairGenerator keyPairGen = null;
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return false;
		}
		
		KeyPair keyPair = keyPairGen.generateKeyPair();
		
		String subject = access.getSubject();
		
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				 new X500Principal(subject),
				 BigInteger.valueOf(System.currentTimeMillis())
				 .multiply(BigInteger.valueOf(10)),
				 access.getNotBefore(),
				 access.getNotAfter(),
				 new X500Principal(subject),
				 keyPair.getPublic());
		
		// Extensions
		
		// Key usage
		if(access.isCritical(Constants.KU)) { 
			boolean [] usage = access.getKeyUsage();
			int usageValue = 0;
			
			for(int i=0; i<9; i++) {
				if(usage[i]) {
					switch(i){
				    	case 0: usageValue |= KeyUsage.digitalSignature; break;
				    	case 1: usageValue |= KeyUsage.nonRepudiation; break;
				    	case 2: usageValue |= KeyUsage.keyEncipherment; break;
				    	case 3: usageValue |= KeyUsage.dataEncipherment; break;
				    	case 4: usageValue |= KeyUsage.keyAgreement; break;
				    	case 5: usageValue |= KeyUsage.keyCertSign; break;
				    	case 6: usageValue |= KeyUsage.cRLSign; break;
				    	case 7: usageValue |= KeyUsage.encipherOnly; break;
				    	case 8: usageValue |= KeyUsage.decipherOnly; break;
			    	}
				}
			}
			KeyUsage extension = new KeyUsage(usageValue);
			try {
				builder.addExtension(Extension.keyUsage, true, new KeyUsage(usageValue));
			} catch (CertIOException e) {
				e.printStackTrace();
			}
		}
		
		// TODO Subject alternative name
		if(access.isCritical(Constants.SAN)) {
			String[] options = {"othername", "rfc822name", "dnsname", "x400address", "directoryname", "edipartyname", "uriname", "ipaddress", "registeredid"};
			String[] altNames = access.getAlternativeName(Constants.SAN);
			GeneralName[] names = new GeneralName[altNames.length];
			int iter = 0;
			for(String name: altNames) {
				String[] split = name.split("=");
				split[0] = split[0].toLowerCase();
				int i;
				for(i=0; i< options.length; i++) {
					if (split[0].equals(options[i])) {
						names[iter] = new GeneralName(i, name);
						iter++;
						break;
					}
				}
				if (i==9) {
					access.reportError("Bad subject alternative name type.");
					return false;
				}
			}
			try {
				builder.addExtension(Extension.subjectAlternativeName, true, new GeneralNames(names));
			} catch (CertIOException e) {
				e.printStackTrace();
				return false;
			}
		}
		
		
		// Inhibit any policy
		if(access.isCritical(Constants.IAP) && access.getInhibitAnyPolicy()) {
			ASN1Integer skipCertsInteger = new ASN1Integer(new BigInteger(access.getSkipCerts()));
			try {
				builder.addExtension(Extension.inhibitAnyPolicy, true, skipCertsInteger);
			} catch (CertIOException e) {
				e.printStackTrace();
				return false;
			}
		}
		
		// Save
		
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(
				access.getPublicKeyDigestAlgorithm());

		ContentSigner signer = null;
		try {
			signer = csBuilder.build(keyPair.getPrivate());
		} catch (OperatorCreationException e) {
			e.printStackTrace();
			return false;
		}

		X509CertificateHolder holder = builder.build(signer);
		java.security.cert.X509Certificate cert = null;
		try {
			cert = new JcaX509CertificateConverter().setProvider("BC")
					.getCertificate(holder);
		} catch (CertificateException e) {
			e.printStackTrace();
			return false;
		}
		
		try (FileOutputStream os = new FileOutputStream(new File(this.keystore_file))) {
			keyStore.setKeyEntry(arg0, keyPair.getPrivate(), this.keystore_pass.toCharArray(), new X509Certificate[] {cert});
			keyStore.store(os, this.keystore_pass.toCharArray());
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
			e.printStackTrace();
			return false;
		}
		
		
		return true;
	}

	@Override // file, keypair, algorithm
	public boolean signCSR(String arg0, String arg1, String arg2) {
		try {
			ContentSigner cs = new JcaContentSignerBuilder(arg2).build((PrivateKey)keyStore.getKey(arg1, keystore_pass.toCharArray()));
			X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) keyStore.getCertificate(arg1)).getSubject();
			BigInteger serial = new BigInteger(access.getSerialNumber());
			Date notBefore = access.getNotBefore();
			Date notAfter = access.getNotAfter();
			X500Name subject = currentCsr.getSubject();
            PublicKey publicKey = new JcaPKCS10CertificationRequest(currentCsr).setProvider(new BouncyCastleProvider()).getPublicKey();

			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subject, publicKey);
			
			// TODO exkstenzije
			
			PrivateKey pk = (PrivateKey) keyStore.getKey(arg1, keystore_pass.toCharArray());
            ContentSigner signer = new JcaContentSignerBuilder(arg2).setProvider(new BouncyCastleProvider()).build(pk);
			
			X509CertificateHolder signed = builder.build(signer);
			
			ArrayList<X509CertificateHolder> chain = new ArrayList<>();
			chain.add(signed);
			for(java.security.cert.Certificate c: keyStore.getCertificateChain(arg1)) {
				chain.add(new JcaX509CertificateHolder((X509Certificate)c));
			}
			
			
			 CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
	         generator.addCertificates(new CollectionStore<>(chain));

            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(signed.getEncoded()));

            try (FileOutputStream os = new FileOutputStream(new File(arg0))) {
                os.write(signedData.getEncoded());
            }

            return true;
			
					
		} catch (UnrecoverableKeyException | OperatorCreationException | KeyStoreException
				| NoSuchAlgorithmException | CertificateEncodingException | InvalidKeyException | CMSException | IOException e) {
			e.printStackTrace();
		}
		
		return false;
	}

}
