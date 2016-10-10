import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * Simple routine to encrypt and decrypt using a Public and Private key with
 * passphrase. This service routine provides the basic PGP services between byte
 * arrays.
 * 
 */
public class PgpDecryption {

	private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException {
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
		System.out.println("PGP Secret key :: " + pgpSecKey);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey.extractPrivateKey(pass, "BC");
	}

	/**
	 * decrypt the passed in message stream
	 * 
	 * @param encrypted
	 *            The message to be decrypted.
	 * @param passPhrase
	 *            Pass phrase (key)
	 * 
	 * @return Clear text as a byte array. I18N considerations are not handled
	 *         by this routine
	 * @exception IOException
	 * @exception PGPException
	 * @exception NoSuchProviderException
	 */
	public static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password) throws IOException, PGPException, NoSuchProviderException {
		InputStream in = new ByteArrayInputStream(encrypted);
		in = PGPUtil.getDecoderStream(in);
		System.out.println("Input stream of encrypted data :: " + in);

		PGPObjectFactory pgpF = new PGPObjectFactory(in);
		System.out.println("PGPObjectFactory :: " + pgpF);

		PGPEncryptedDataList enc = null;
		Object o = pgpF.nextObject();
		System.out.println("PGPObjectFactory object :: " + o);
		enc = o instanceof PGPEncryptedDataList ? (PGPEncryptedDataList) o : (PGPEncryptedDataList) pgpF.nextObject();
		System.out.println("PGPEncryptedDataList :: " + enc);

		// find the secret key
		@SuppressWarnings("rawtypes")
		Iterator it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;

		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
		System.out.println("Encrypted data object :: " + it);
		while (sKey == null && it.hasNext()) {
			pbe = (PGPPublicKeyEncryptedData) it.next();
			sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
		}

		if (sKey == null) {
			throw new IllegalArgumentException("secret key for message not found.");
		}

		System.out.println("PGPPublicKeyEncryptedData :: " + pbe);
		System.out.println("PGPPrivateKey :: " + sKey);

		InputStream clear = pbe.getDataStream(sKey, "BC");
		System.out.println("InputStream from PGPPrivateKey :: " + clear);

		PGPObjectFactory pgpFact = new PGPObjectFactory(clear);
		System.out.println("PGPObjectFactory :: " + pgpFact);

		PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
		System.out.println("PGPOnePassSignatureList :: " + p1);

		PGPOnePassSignature ops = p1.get(0);
		System.out.println("PGPOnePassSignature :: " + ops);

		PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
		System.out.println("PGPLiteralData :: " + p2);

		InputStream dIn = p2.getInputStream();
		System.out.println("Input stream of PGPLiteralData :: " + dIn);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int ch = 0;

		System.out.println("Read input stream :: " + dIn.read());
		while ((ch = dIn.read()) >= 0) {
			out.write(ch);
		}

		byte[] returnBytes = out.toByteArray();
		out.close();
		System.out.println("Final data in bytes :: " + returnBytes);
		return returnBytes;
	}

	public static byte[] getBytesFromFile(File file) throws IOException {
		InputStream is = new FileInputStream(file);

		// Get the size of the file
		long length = file.length();

		if (length > Integer.MAX_VALUE) {
			// File is too large
		}

		// Create the byte array to hold the data
		byte[] bytes = new byte[(int) length];

		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}

		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file " + file.getName());
		}

		// Close the input stream and return bytes
		is.close();
		return bytes;
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("Added Security provider - BC");
		for (int i = 0; i < Security.getProviders().length; i++) {
			System.out.println(Security.getProviders()[i].getName() + " - " + Security.getProviders()[i].getInfo() + " - " + Security.getProviders()[i].getVersion());
		}

		byte[] encFromFile = getBytesFromFile(new File("C:/Users/achhabra/Desktop/TRP/TCContactsWorkday040616110200.csv.pgp"));
		FileInputStream secKey = new FileInputStream("C:/Users/achhabra/Desktop/TRP/trowekeyP.pgp.asc");

		byte[] decrypted = decrypt(encFromFile, secKey, "T@o3eM!t&a*e$hDev".toCharArray());
		System.out.println("\ndecrypted data = '" + new String(decrypted) + "'");

	}
}