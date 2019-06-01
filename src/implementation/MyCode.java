package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;
import javax.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

}
