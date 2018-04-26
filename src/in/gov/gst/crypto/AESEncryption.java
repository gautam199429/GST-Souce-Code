/*******************************************************************************
 * DISCLAIMER: The sample code or utility or tool described herein
 *    is provided on an "as is" basis, without warranty of any kind.
 *    GSTN does not warrant or guarantee the individual success
 *    developers may have in implementing the sample code on their
 *    environment. 
 *    
 *    GSTN  does not warrant, guarantee or make any representations
 *    of any kind with respect to the sample code and does not make
 *    any representations or warranties regarding the use, results
 *    of use, accuracy, timeliness or completeness of any data or
 *    information relating to the sample code. UIDAI disclaims all
 *    warranties, express or implied, and in particular, disclaims
 *    all warranties of merchantability, fitness for a particular
 *    purpose, and warranties related to the code, or any service
 *    or software related thereto. 
 *    
 *   GSTN  is not responsible for and shall not be liable directly
 *    or indirectly for any direct, indirect damages or costs of any
 *    type arising out of use or any action taken by you or others
 *    related to the sample code.
 *    
 *    THIS IS NOT A SUPPORTED SOFTWARE.
 ******************************************************************************/
package in.gov.gst.crypto;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AESEncryption {
	
	public static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	public static final String AES_ALGORITHM = "AES";
	public static final int ENC_BITS = 256;
	public static final String CHARACTER_ENCODING = "UTF-8";
	private static Cipher ENCRYPT_CIPHER;
	private static Cipher DECRYPT_CIPHER;
	private static KeyGenerator KEYGEN;
	
	static{
		try{
			ENCRYPT_CIPHER = Cipher.getInstance(AES_TRANSFORMATION);
			DECRYPT_CIPHER = Cipher.getInstance(AES_TRANSFORMATION);
			KEYGEN = KeyGenerator.getInstance(AES_ALGORITHM);
			KEYGEN.init(ENC_BITS);
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	/**
     * This method is used to encode bytes[] to base64 string.
     * 
      * @param bytes
     *            : Bytes to encode
     * @return : Encoded Base64 String
     */
   private static String encodeBase64String(byte[] bytes) {
         return new String(java.util.Base64.getEncoder().encode(bytes));
   }
   /**
    * This method is used to decode the base64 encoded string to byte[]
    * 
     * @param stringData
    *            : String to decode
    * @return : decoded String
    * @throws UnsupportedEncodingException
    */
   private static byte[] decodeBase64StringTOByte(String stringData) throws Exception {
		return java.util.Base64.getDecoder().decode(stringData.getBytes(CHARACTER_ENCODING));
	}
   
   /**
    * This method is used to generate the base64 encoded secure AES 256 key     * 
    * @return : base64 encoded secure Key
    * @throws NoSuchAlgorithmException
    * @throws IOException
    */
	private static String generateSecureKey() throws Exception{
		SecretKey secretKey = KEYGEN.generateKey();
		System.out.println(secretKey);
		return encodeBase64String(secretKey.getEncoded());
		
	}
    /**
    * This method is used to encrypt the string which is passed to it as byte[] and return base64 encoded
    * encrypted String
     * @param plainText
    *            : byte[]
    * @param secret
    *            : Key using for encrypt
    * @return : base64 encoded of encrypted string.
    * 
    */
	
	private static String encryptEK(byte[] plainText, byte[] secret){
		try{
			
			SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
			ENCRYPT_CIPHER.init(Cipher.ENCRYPT_MODE, sk);
			return Base64.encodeBase64String(ENCRYPT_CIPHER
                     .doFinal(plainText));
			
		}catch(Exception e){
			e.printStackTrace();
			return "";
		}
	}
	
	
	/**
    * This method is used to decrypt base64 encoded string using an AES 256 bit key.
    * 
     * @param plainText
    *            : plain text to decrypt
    * @param secret
    *            : key to decrypt
    * @return : Decrypted String
    * @throws IOException
    * @throws InvalidKeyException
    * @throws BadPaddingException
    * @throws IllegalBlockSizeException
    */
    public static byte[] decrypt(String plainText, byte[] secret)
                throws InvalidKeyException, IOException, IllegalBlockSizeException,
                BadPaddingException,Exception {
		SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
		System.out.println(sk);
		DECRYPT_CIPHER.init(Cipher.DECRYPT_MODE, sk);		
          return DECRYPT_CIPHER.doFinal(Base64.decodeBase64(plainText));
    }
    public static byte[] authEk() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception
    {
    	String sek= "3Yx53NvqfX473QUsGrjlB1Ss6mHEXodjwx8n7akfZiZYYaIrBdVh9gFjWj22OQUG";
    	byte[] authEK = AESEncryption.decrypt(sek, decodeBase64StringTOByte("Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8="));
    	System.out.println(authEK);
    	
		return authEK;
    	
    }
    
    public static String encryjson() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception
    {
    	
    String encodedjson="";
    	byte[] enc = encodedjson.getBytes();
    //		byte [] authek = "[B@35851384";
    	byte[] authEK = AESEncryption.decrypt("3Yx53NvqfX473QUsGrjlB1Ss6mHEXodjwx8n7akfZiZYYaIrBdVh9gFjWj22OQUG", decodeBase64StringTOByte("Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8="));
    	System.out.println(authEK);
    	String encjson = AESEncryption.encryptEK(enc,authEK);
    	System.out.println("Encrypted Json:------"+encjson);
    	String hmackey = AESEncryption.generateHmac(encodedjson, authEK);
    	System.out.println("hmac:-----"+hmackey);
    	String jsonData = new String(decodeBase64StringTOByte(new String(decrypt(encjson, authEK))));
    	System.out.println(jsonData);
    	return null;
    	
    }
    
    
    private static void produceSampleData(){
    	try {
			//Generation of app key. this will be in encoded.
			String appkey = generateSecureKey();
			System.out.println("App key in encoded :"+ appkey);
			//Encrypt with GSTN public key
			String encryptedAppkey = EncryptionUtil.generateEncAppkey(decodeBase64StringTOByte(appkey));
			System.out.println("Encrypted App Key :"+ encryptedAppkey);
			
					
			//Generation of OTP with appkey
			String otp = "795674";
			String encryptedOtp = encryptEK(otp.getBytes(),decodeBase64StringTOByte("0g1/JNhjsaqqJIzlZVDuv6A0Yog6amLWX9UC+BoaQWo="));
			System.out.println("Encrypted OTP :"+encryptedOtp);
			
				
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }   
    public static String generateHmac(String data, byte[] ek)
    {
    	String hash = null;
    	try{ 
	    	Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
	        SecretKeySpec secret_key = new SecretKeySpec(ek, "HmacSHA256");
	        System.out.println(secret_key);
	        sha256_HMAC.init(secret_key);
	        hash = Base64.encodeBase64String(sha256_HMAC.doFinal(data.getBytes()));
	        System.out.println(hash);
    	}catch(Exception e){
    		e.printStackTrace();
    	}   	
		return hash;
    }
	public static void main(String args[])throws Exception{

//		encryjson();
////	authEk();
		produceSampleData();
	}
}

// Encoded payload = eyJnc3RpbiI6ICIyN0JDQU1IMDQ5OEMxWjMiLCJmcCI6ICIwNzIwMTciLCJndCI6IDM3ODI5NjkuMDEsImN1cl9ndCI6IDM3ODI5NjkuMDEsImIyYiI6IFt7ImN0aW4iOiAiMjdCQ0FNSDA0OThDMVozIiwiaW52IjogW3siaW51bSI6ICJTMDA4NDAwIiwiaWR0IjogIjI0LTExLTIwMTYiLCJ2YWwiOiA3MjkyNDguMTYsInBvcyI6ICIwNiIsInJjaHJnIjogIk4iLCJldGluIjogIjI3QkNBTUgwNDk4QzFaMyIsImludl90eXAiOiAiUiIsIml0bXMiOiBbeyJudW0iOiAxLCJpdG1fZGV0IjogeyJydCI6IDUsInR4dmFsIjogMTAwMDAsImlhbXQiOiA4MzMuMzMsImNzYW10IjogNTAwfX1dfV19XX0=
//javax.crypto.spec.SecretKeySpec@15fda
//App key in encoded :0g1/JNhjsaqqJIzlZVDuv6A0Yog6amLWX9UC+BoaQWo=
//Encrypted App Key :f8DAI/QQHDpC8fVybDjTfhJBeI7r3JuZz56kf/0ODMMYHSGcTr7MH2TWZ3Panqf+Ee2f1cgA1ruchqw+RdFfjBGFD2go9zQALVc2Z1p5AS/4kyQteTYHtU5WPXtIBlehkz3BBrTZQUp/FI9LgLBNNu4omVQ0G3zueKoZyIyLhrb7WYQ4M00WFbEGaneZqk2G5VQGZBOLjeiicL7KBBCYRTcdNSbcKwglRv0YKNwcYjkNfBVxW3cnFNrITK3n3hx4u1vSwGwyyL+LLdRti/0GpabtkMBsUjXlB8aRpd6g4vVPTFZ3YltwYd2zI+QPjiswuuF0VFiVG8Z5ugb2ILbfaQ==

