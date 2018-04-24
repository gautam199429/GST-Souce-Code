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
		DECRYPT_CIPHER.init(Cipher.DECRYPT_MODE, sk);		
          return DECRYPT_CIPHER.doFinal(Base64.decodeBase64(plainText));
    }
    public static byte[] authEk() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception
    {
    	String sek= "fouulUffg9w1vsWon5muvyQLzhZkRr9beQqYDs+P82tYYaIrBdVh9gFjWj22OQUG";
    	byte[] authEK = AESEncryption.decrypt(sek, decodeBase64StringTOByte("Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8="));
    	System.out.println(authEK);
		return authEK;
    	
    }
    
    public static String encryjson() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception
    {
    	
    String encodedjson="ew0KICAgICJnc3RpbiI6ICIzM1RDQVROMjMxNEExWlQiLA0KICAgICJmcCI6ICIwNzIwMTciLA0KICAgICJndCI6IDM3ODI5NjkuMDEsDQogICAgImN1cl9ndCI6IDM3ODI5NjkuMDEsDQogICAgImIyYiI6IFsNCiAgICAgICAgew0KICAgICAgICAgICAgImN0aW4iOiAiMDFBQUJDRTIyMDdSMUM1IiwNCiAgICAgICAgICAgICJpbnYiOiBbDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAiaW51bSI6ICJTMDA4NDAwIiwNCiAgICAgICAgICAgICAgICAgICAgImlkdCI6ICIyNC0xMS0yMDE2IiwNCiAgICAgICAgICAgICAgICAgICAgInZhbCI6IDcyOTI0OC4xNiwNCiAgICAgICAgICAgICAgICAgICAgInBvcyI6ICIwNiIsDQogICAgICAgICAgICAgICAgICAgICJyY2hyZyI6ICJOIiwNCiAgICAgICAgICAgICAgICAgICAgImV0aW4iOiAiMDFBQUJDRTU1MDdSMUM0IiwNCiAgICAgICAgICAgICAgICAgICAgImludl90eXAiOiAiUiIsDQogICAgICAgICAgICAgICAgICAgICJpdG1zIjogWw0KICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICJudW0iOiAxLA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICJpdG1fZGV0Ijogew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicnQiOiA1LA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAidHh2YWwiOiAxMDAwMCwNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImlhbXQiOiA4MzMuMzMsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJjc2FtdCI6IDUwMA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgICAgXQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgIF0NCiAgICAgICAgfQ0KICAgIF0NCn0=";
    	byte[] enc = encodedjson.getBytes();
    //		byte [] authek = "[B@35851384";
    	byte[] authEK = AESEncryption.decrypt("fouulUffg9w1vsWon5muvyQLzhZkRr9beQqYDs+P82tYYaIrBdVh9gFjWj22OQUG", decodeBase64StringTOByte("Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8="));
    	System.out.println(authEK);
    	String encjson = AESEncryption.encryptEK(enc,authEK);
    	System.out.println(encjson);
    	String hmackey = AESEncryption.generateHmac(encodedjson, authEK);
    	System.out.println(hmackey);
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
			String otp = "585225";
			String encryptedOtp = encryptEK(otp.getBytes(),decodeBase64StringTOByte("Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8="));
			System.out.println("Encrypted OTP :"+encryptedOtp);
			
				
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
//    public static void testData(){
//		try {
//			
//			
//			String decrypted_appkey = "41+sD/gm9DWQeZbJm98qb3ss9Eu96XkClU5a4hyfaAw=";
//			String receivedSEK = "yDWrI0m6juY+MKsPNtWkBYJAVsE0XIQvAJwv+P2T9DgOLzbTmU1E5NkewRcnIsK2";
//			String gotREK = "QdwtOmbHgs5+T6XguaXrJtXyc1EpapQzuV5wWgEiDbUdShGCyOtl6JelLUI/R5xt";
//			String data="czI9UduToC0S2M/Z8NxmD6AaiCHqK/wN4cLnpjje1LCgo7hXhoGvSUac0BB9umkBnWEO+osui4ZZHZIHrO8bvMlQI5mmyuqDxqLTg5IkgYCzUnDWGV6qP/6ei2J8eCKLxqv0XALN228h0QhNK4nr3Q9n4HVGngdXJf1dSIcxNVXQaJTctti1w7n6bm5Ht2FlMVKsIT7O8bwD9OyJtV0Z0jZa45DoWMxIwbRQKTnBCzC7+gCWSBriGW1Bsc4AGMzQks8qE0y1rQscgtPp8D6/eHjIT5e3jwn9EWYZdgDb+y1sCaUL77AEvKm9inM3fyfj3yw11I31NX79KVFzKCOFA3gfuz2RhTZ5QnxuUABGuHXDrLKaYkkxa6f0GPBDJmUqs5/R1w2YjpOzdDG+i0zRjPvIdSpM4wzVt0dB449TplAftdPkLCmVKBovrLe8OwE58nI5j63Kr8JMFc/V8XBFDpRDZl4EgdLeKWX4rop67GeWUVjdIyyAuiOiXTi/v9r1EGpFzybDJE2Z9S2/ntK5iVsPT6Bn4MaqkTiOG5D3eh5aDNuM3mToDC6LSD7PkX9Ekt1R/T1dLeKDOnEo5aQqCcqm/v5A9AZw86nyzFPfdjLfl9TOem4/hSP8Xslx645jnhUlr3kkshw5LzRpx5KaC32PC+eOcRq6MEeVF6vStvA/XA/9dRazxwvPnS4z09gtSdZRozls1UmNjBkhSoh4tDSU0lQXIsrmr/tGtLSsj1fH7h5De+qBvhyvY3LOw6CGfq3dKUFcE0n4yLosMIm2xbtVzROGdNXgDmUPUmk9wXHLc5UA8GNY9rq1z1ypCBbYpHLCQ9NHLncweF2FOK2obqF3kioypUbPxndgtd4cbVReXf9XBL9YkkxDCvNjH44bz0ciVnhg9jwGETLU6z40/s3ew8dDrNCbUmrGK42YxB44Ljwk5RQBRa5uMJnrFKiR8dnUJZai12moHO6GzIg5yiYEEa65rbzgdJOozcjTXgLl2Mf1uR4jN3Y7+u/e4OcYNHlF2Jd/7EGH+sJ9aOIYsq0K8f82o4jbbInhSg37pv2Kf5fm6urd4UoQUJ01fGGOHytSegKX2wO9vlKhHyrbu1+zMnfjEXabjENTlLWS5npkDhO7CaVsK4XsxTucsSdXKg3w7n82C05acOwrvewHCMNWD1IZuuKKcHWLhd7khs0gGRSQR4eKbN17fuYg2aTkQM/n1/8/NZP35UsMt+w9zpewE1wQr6C4guFoiIS1IUReJwFqCBAHsyXCnSdVjZlzZu40KYGWjR3TmkG4vVZA22cxsq83Oc/aykrflL0f1QI6txyfqSZAlpNEqKHerDR/iGAgwYa5f9y8Id7hnyK1lU0NnkAbKbBh9GWuvtBiNL7AvrDNMLt2lStyuDhh0TTscAqFv26jjAtz2MoEZ9HPvoBPDAsxq0HGFeoypyeQKZI0/xTh+iVcsMxgqY5FeOEiWEW/cBBJZOP402+319jDlDoSRerbUKwP63TLxE/zL2j4YyxHTEWi9PUiF+JosUHmza9PiyTdbIxyrhxXDfKVoQ==";			
//			byte[] authEK = decrypt(receivedSEK, decodeBase64StringTOByte(decrypted_appkey));
//			System.out.println("Encoded Auth EK (Received):"+ encodeBase64String(authEK));			
//			byte[] apiEK = decrypt(gotREK, authEK);
//			System.out.println("Encoded Api EK (Received):"+ encodeBase64String(apiEK));
//			String jsonData = new String(decodeBase64StringTOByte(new String(decrypt(data, apiEK))));
//			System.out.println(jsonData);			
//		}  catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//    }    
    public static String generateHmac(String data, byte[] ek)
    {
    	String hash = null;
    	try{ 
	    	Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
	        SecretKeySpec secret_key = new SecretKeySpec(ek, "HmacSHA256");
	        sha256_HMAC.init(secret_key);
	        hash = Base64.encodeBase64String(sha256_HMAC.doFinal(data.getBytes()));
	        System.out.println(hash);
    	}catch(Exception e){
    		e.printStackTrace();
    	}   	
		return hash;
    }
	public static void main(String args[])throws Exception{
		
//        String payloaddata = "ew0KICAgICJnc3RpbiI6ICIyN0FIUVBBNzU4OEwxWkoiLA0KICAgICJmcCI6ICIxMjIwMTYiLA0KICAgICJndCI6IDM3ODI5NjkuMDEsDQogICAgImN1cl9ndCI6IDM3ODI5NjkuMDEsDQogICAgInZlcnNpb24iOiAiR1NUMS4yIiwNCiAgICAiaGFzaCI6ICJHU1RSMS1IYXNoLUNvZGUiLA0KICAgICJtb2RlIjogIm9mIiwNCiAgICAiYjJiIjogWw0KICAgICAgICB7DQogICAgICAgICAgICAiY3RpbiI6ICIwMUFBQkNFMjIwN1IxQzUiLA0KICAgICAgICAgICAgImludiI6IFsNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICJpbnVtIjogIlMwMDg0MDAiLA0KICAgICAgICAgICAgICAgICAgICAiaWR0IjogIjI0LTExLTIwMTYiLA0KICAgICAgICAgICAgICAgICAgICAidmFsIjogNzI5MjQ4LjE2LA0KICAgICAgICAgICAgICAgICAgICAicG9zIjogIjA2IiwNCiAgICAgICAgICAgICAgICAgICAgInJjaHJnIjogIk4iLA0KICAgICAgICAgICAgICAgICAgICAiZXRpbiI6ICIwMUFBQkNFNTUwN1IxQzQiLA0KICAgICAgICAgICAgICAgICAgICAiaW52X3R5cCI6ICJSIiwNCiAgICAgICAgICAgICAgICAgICAgIml0bXMiOiBbDQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIm51bSI6IDEsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIml0bV9kZXQiOiB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJydCI6IDUsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJ0eHZhbCI6IDEwMDAwLA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiaWFtdCI6IDgzMy4zMywNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImNzYW10IjogNTAwDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICBdDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgXQ0KICAgICAgICB9DQogICAgXQ0KfQ==";
//		String sek = "jaQiBVlBYd0nikdsebSNoWPK7TlszsuxKamoqquWM1tCvOWIq5hU54tlGD0RDI2u";
//		byte[] sek1 = sek.getBytes();
//		generateHmac(payloaddata, sek1);
//produceSampleData();
		encryjson();
	}
}

//App key in encoded :Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8=
//Encrypted App Key :yGyvipLHlL7ig9FnI3igbC/cYZde6NadzgWZ8pHgQX7y2coQl6W+rGA+nxB+QDu5QzGQ1Y77/1eG718TJ5h3FgrKhghIybe2ecuSVQz6S4s/GEZhV+grU+/gqaFInQLs+F6Ne2yjAVgii3UlYs9tKZH8X4mORUvgxBirJUweZsjWy5F//KzvmziYhno9MXGahs7Qr+04A/69z6FbDavIeTyp28qnRYTEtZGi30Nzj2jUXZlGAbrw1zR+FBUuYXMKYzKHDn338/Ij9TFtMPMtHjkqbHw6qbwyShyQQfqCr9AbbiksSM7UrVjquEigEnOupkHBdhrOjSSncrmYYTCXeg==
//Encrypted OTP :kOKhT6v2lPIcC6jrBDA1Fg==


//{
//    "status_cd": "1",
//    "auth_token": "46c8db2decd24f438c2a3f5df29bae50",
//    "expiry": 120,
//    "sek": "fouulUffg9w1vsWon5muvyQLzhZkRr9beQqYDs+P82tYYaIrBdVh9gFjWj22OQUG"
//}

//authsek [B@35851384

// Encode jason= ew0KICAgICJnc3RpbiI6ICIzM1RBQlROMTM0MEMxWlMiLA0KICAgICJmcCI6ICIwNzIwMTciLA0KICAgICJndCI6IDM3ODI5NjkuMDEsDQogICAgImN1cl9ndCI6IDM3ODI5NjkuMDEsDQogICAgInZlcnNpb24iOiAiR1NUMS4yIiwNCiAgICAiaGFzaCI6ICJHU1RSMS1IYXNoLUNvZGUiLA0KICAgICJtb2RlIjogIm9mIiwNCiAgICAiYjJiIjogWw0KICAgICAgICB7DQogICAgICAgICAgICAiY3RpbiI6ICIwMUFBQkNFMjIwN1IxQzUiLA0KICAgICAgICAgICAgImludiI6IFsNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICJpbnVtIjogIlMwMDg0MDAiLA0KICAgICAgICAgICAgICAgICAgICAiaWR0IjogIjI0LTExLTIwMTYiLA0KICAgICAgICAgICAgICAgICAgICAidmFsIjogNzI5MjQ4LjE2LA0KICAgICAgICAgICAgICAgICAgICAicG9zIjogIjA2IiwNCiAgICAgICAgICAgICAgICAgICAgInJjaHJnIjogIk4iLA0KICAgICAgICAgICAgICAgICAgICAiZXRpbiI6ICIwMUFBQkNFNTUwN1IxQzQiLA0KICAgICAgICAgICAgICAgICAgICAiaW52X3R5cCI6ICJSIiwNCiAgICAgICAgICAgICAgICAgICAgIml0bXMiOiBbDQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIm51bSI6IDEsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIml0bV9kZXQiOiB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJydCI6IDUsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJ0eHZhbCI6IDEwMDAwLA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiaWFtdCI6IDgzMy4zMywNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImNzYW10IjogNTAwDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICBdDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgXQ0KICAgICAgICB9DQogICAgXQ0KfQ==
// hmac = 4dhs8dxnWW3yeIeUIPNVJnflC3yniZHshpdb3/kqFvE=
// Enc json= ye3SRSNF0GrEmHElaC0szkxRf7sJmGLma47T9FijGB3Dp8iZ4yZHG9r3th0aKGNpvyO2CIvkNz6OqZ8Tjy4iuLaTs5Qu5QB0vB99UU3f9IbPEgpNA+TskkTgK/ktguXDLmP3t7gobrGIb5kG99AdUt1EYuZd1xMmn3y0TxnqxIeU4w9s1dsWuHm1Lczo0UzB2irdxLJ3oPxmd+61qgJ4zkPj0fisKPNJnJJHUDuM22nb8Xy5iJpwNQ8bRSyvRpPuWa3k0r03AFdKrFZgf6EmLGqXQopDXuz7OofsthfulbxTrkSTwOUwMuC6JdGxpwMA2fYX2AlUySRGvre1dWcVVyjHAcXp0Hke8eYkbXSUyAN63mNHpYT0dsEhLBTgZc4XUKti0VkGP14XjN/+BTWBqHOuDuQd+lszk8Ze2f4r7KeGRIihAfvi4qhp4prVVf/vYk321GSeuZGYWT21v5Bl/97XW++1heMyRoWC9Nn3G4m1hBYjU+ffbxlcbNST6Y74z09c2/+65BETbM3GhsfZFONZrFSIiUbXFNiA1oMSN5Eag6y4VWvQ50J7EZ2X1H79DmlrVTuJRpiThRxFcKJMF/zAMBwB/FBxZc7NP9ATIuz9W9aURm5PwuAG4O7YpKvcFVotOB+KSn4J5rQ2+REWY/zAMBwB/FBxZc7NP9ATIuzPjOa+Ui2BPozRkzcSF2jErX/Y9k4Q5rczGkds0x5g6DzlXUbPnN+0lEev2aV3h3CfWIJ3sfIzAl/8H0okV/OqBscBGw0zPPufHjfUOAJ3s55IXYv55AVOyDW5eoWwo6v7KGH8prQa3fy3N2ot2aPTGfmblcukT9Y3+k/Ma8onb/zAMBwB/FBxZc7NP9ATIuxjJTtSZ6GgEsvCAc0nIegCk9P9w2mRHMQET5Q/2X4jQUAaVa6J/upF17iDrmOqMuT8wDAcAfxQcWXOzT/QEyLspdQdr5Mom0MzygtPlvTSIgxdv2f6g88AyLekBhAJJ5CeSF2L+eQFTsg1uXqFsKOr5dmv72xcCXeTtrIYWtjcNhRmHemHDnPcpYOiKzYQcmr8wDAcAfxQcWXOzT/QEyLs7MThuUFIkBRySYgE7BvI8/zAMBwB/FBxZc7NP9ATIuz8wDAcAfxQcWXOzT/QEyLsHurSs/G+csj+8A8tVjpFB89PXNv/uuQRE2zNxobH2RT8wDAcAfxQcWXOzT/QEyLsagM4O7VAlSESZ40RjxfOiciciHPJr+JW+gSsCmCzyWL8wDAcAfxQcWXOzT/QEyLs/MAwHAH8UHFlzs0/0BMi7NkTIK59Bov9yFiaLw14/+3PT1zb/7rkERNszcaGx9kU/MAwHAH8UHFlzs0/0BMi7HpihOGyjHZs5jyiCkZjYF1b4SX4cjFfeqKleMQQMJHPPOVdRs+c37SUR6/ZpXeHcPzAMBwB/FBxZc7NP9ATIuyfWIJ3sfIzAl/8H0okV/Oq39Fst8ywXebChbIIrv8stq5VBnqdkdrXOG0cVCFGtKP8wDAcAfxQcWXOzT/QEyLs/MAwHAH8UHFlzs0/0BMi7BodLFFyeHSjSoPeEH0sBjHPT1zb/7rkERNszcaGx9kU/MAwHAH8UHFlzs0/0BMi7LGpT+CxEwVP5ykT8WXtRgL8wDAcAfxQcWXOzT/QEyLsP6zTSak4DCBvWrmksy8OsfzAMBwB/FBxZc7NP9ATIuzBAa33id6nfYD96w3+1RkX/MAwHAH8UHFlzs0/0BMi7K/cmrfu/iGFPNElds+yXuVtYXNHI+TLcEvHYNYVdpALuqlbyL9lDHlJJ7QcGlSCGHlfXV7o/eBF+dLGAOz2Eso=