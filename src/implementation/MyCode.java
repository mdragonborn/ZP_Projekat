package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	private final String keystore_file = "local_keystore.p12"; 
	private final String keystore_pass = "qwe123";
	
	private KeyStore keyStore;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean canSign(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSubjectInfo(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String importCSR(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean importCertificate(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int loadKeypair(String arg0) {
		X509Certificate cert = null;
		try {
			cert = (X509Certificate) this.keyStore.getCertificate(arg0);
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
		
		return 0;
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
		// TODO Auto-generated method stub
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
		System.out.println(access.getPublicKeyParameter());
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
				if(usage[i])
					usageValue |= i;
			}
			KeyUsage extension = new KeyUsage(usageValue);
			try {
				builder.addExtension(Extension.keyUsage, true, extension);
			} catch (CertIOException e) {
				e.printStackTrace();
			}
		}
		
		// Subject alternative name
		if(access.isCritical(Constants.SAN)) {
			String[] options = {"othername", "rfc822name", "dnsname", "x400address", "directoryname", "edipartyname", "uniformresourceidentifier", "ipaddress", "registeredid"};
			String[] altNames = access.getAlternativeName(Constants.SAN);
			GeneralName[] names = new GeneralName[altNames.length];
			int iter = 0;
			for(String name: altNames) {
				String[] split = name.split("=");
				split[0] = split[0].toLowerCase();
				int i;
				for(i=0; i< options.length; i++) {
					if (split[0].equals(options[i])) {
						System.out.println(i + " " + split[1]);
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
				// TODO Auto-generated catch block
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
				// TODO Auto-generated catch block
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

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

}
