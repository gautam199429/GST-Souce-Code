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
    	
    String encodedjson="ew0KICAgICJnc3RpbiI6ICIyN0JDQU1IMDQ5OEMxWjMiLA0KICAgICJmcCI6ICIwNzIwMTciLA0KICAgICJndCI6IDM3ODI5NjkuMDEsDQogICAgImN1cl9ndCI6IDM3ODI5NjkuMDEsDQogICAgInZlcnNpb24iOiAiR1NUMS4yIiwNCiAgICAiYjJiIjogWw0KICAgICAgICB7DQogICAgICAgICAgICAiY3RpbiI6ICIwMUFBQkNFMjIwN1IxQzUiLA0KICAgICAgICAgICAgImludiI6IFsNCiAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICJpbnVtIjogIlMwMDg0MDAiLA0KICAgICAgICAgICAgICAgICAgICAiaWR0IjogIjI0LTExLTIwMTYiLA0KICAgICAgICAgICAgICAgICAgICAidmFsIjogNzI5MjQ4LjE2LA0KICAgICAgICAgICAgICAgICAgICAicG9zIjogIjA2IiwNCiAgICAgICAgICAgICAgICAgICAgInJjaHJnIjogIk4iLA0KICAgICAgICAgICAgICAgICAgICAiZXRpbiI6ICIwMUFBQkNFNTUwN1IxQzQiLA0KICAgICAgICAgICAgICAgICAgICAiaW52X3R5cCI6ICJSIiwNCiAgICAgICAgICAgICAgICAgICAgIml0bXMiOiBbDQogICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIm51bSI6IDEsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIml0bV9kZXQiOiB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJydCI6IDUsDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJ0eHZhbCI6IDEwMDAwLA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiaWFtdCI6IDgzMy4zMywNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImNzYW10IjogNTAwDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICAgICBdDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgXQ0KICAgICAgICB9DQogICAgXQ0KfQ==";
    	byte[] enc = encodedjson.getBytes();
    //		byte [] authek = "[B@35851384";
    	byte[] authEK = AESEncryption.decrypt("3Yx53NvqfX473QUsGrjlB1Ss6mHEXodjwx8n7akfZiZYYaIrBdVh9gFjWj22OQUG", decodeBase64StringTOByte("Nq7652e5EAMpgJCUSXLC/TH/9lESVsbSyGhrOKzswC8="));
    	System.out.println(authEK);
    	String encjson = AESEncryption.encryptEK(enc,authEK);
    	System.out.println("Encrypted Json:------"+encjson);
    	String hmackey = AESEncryption.generateHmac(encodedjson, authEK);
    	System.out.println("hmac:-----"+hmackey);
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
//		produceSampleData();
//		encryjson();
		authEk();
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

//Encrypted Json:------ye3SRSNF0GrEmHElaC0szgKq/fjbjD2QJjIPs/TkuXAEj7cGzrTLZtbK35bx+1FFvyO2CIvkNz6OqZ8Tjy4iuLaTs5Qu5QB0vB99UU3f9IbPEgpNA+TskkTgK/ktguXDLmP3t7gobrGIb5kG99AdUt1EYuZd1xMmn3y0TxnqxIeU4w9s1dsWuHm1Lczo0UzB2irdxLJ3oPxmd+61qgJ4zkPj0fisKPNJnJJHUDuM22l3OecQvQ9Wt7vj1Zgz4NYtNyK0kLRptFVlX1mty7y5jM9PXNv/uuQRE2zNxobH2RRFkxGXdqjFvLMQHwbYtqxpDD1WEChO9m/UACiWpOgGh9m/e96W90FjiO32ahVdzbZrxUBY3lEBDsvIvHl3dplM1zfhYnyeJbXHYXjPYzDQxuzE4blBSJAUckmIBOwbyPP8wDAcAfxQcWXOzT/QEyLsYlNIN3jox67FpxzMz+CHTaL23wu3W2NLwTimNF4whg085V1Gz5zftJRHr9mld4dwn1iCd7HyMwJf/B9KJFfzqrAlSDc6ejk97Ke1JXtomq0QLRMCNkmCctoQX2ED7iEy/MAwHAH8UHFlzs0/0BMi7FjHOKFpXcQtJkcm/42udVScwlrOM8J8ZJcT06vD31Y//MAwHAH8UHFlzs0/0BMi7MVHg7kNsplvJ/4kSC2FHiJfYUbgKrvfLLSdh5+LaAaF/MAwHAH8UHFlzs0/0BMi7FZqqPja78PXpUlAy02oAbkiemFu7U1a5/8hkvgddX1m/MAwHAH8UHFlzs0/0BMi7Mq9Nzw3rY+QpXAGPr9/DszR6wrlJDzGKpIo5lwrl8byndaTBHJ80lEEwZtCj/zXYPzAMBwB/FBxZc7NP9ATIuzJwc4EZatgZSxfAzL0Z4ob2WA0D8HqpnllzgxybwzwnvzAMBwB/FBxZc7NP9ATIuwtaxZusUPq5mbFMu1fdwtDOh8Nwd4XRMoEyLsQiQVkCPzAMBwB/FBxZc7NP9ATIux7LcN4WTbhqsETavt2Gne4/MAwHAH8UHFlzs0/0BMi7PzAMBwB/FBxZc7NP9ATIuzYHKSQfu/LG7aaVemdcnwl/MAwHAH8UHFlzs0/0BMi7PzAMBwB/FBxZc7NP9ATIuwYx9Rndhjg/GyPFDlaBa/QWmZ8ds9YqtYXC7FseHUZGfzAMBwB/FBxZc7NP9ATIuz8wDAcAfxQcWXOzT/QEyLs1X5dHZzriMfrblNY9GL8q/zAMBwB/FBxZc7NP9ATIuz8wDAcAfxQcWXOzT/QEyLsqNqGcnM7AblSKM9eAx0OPxmjQTlizIpl8ZF8Frac/lv8wDAcAfxQcWXOzT/QEyLs/MAwHAH8UHFlzs0/0BMi7NiNWMVzjbvweIhrazZU/O1Pk4TpkrCfCJlD2j2W/unxnkhdi/nkBU7INbl6hbCjq/zAMBwB/FBxZc7NP9ATIuydhT1hBaQGuJv2OAaRVhfNaqrLhgtGE8Ncd2pUqP+Wx/zAMBwB/FBxZc7NP9ATIuz8wDAcAfxQcWXOzT/QEyLsr9yat+7+IYU80SV2z7Je5fzAMBwB/FBxZc7NP9ATIuyxqU/gsRMFT+cpE/Fl7UYC/MAwHAH8UHFlzs0/0BMi7GGnzO7f5LahlyNn10B19xH8wDAcAfxQcWXOzT/QEyLsCmFI0ANb7ZtRILQ3xF4ooPs+gMtsmTGGM6K/Vh2ZQ/kKDEv7uhpuWMBlQdC2/qUVsz1tKl7L1zbGoUfe1eGAiA==
//javax.crypto.spec.SecretKeySpec@fa77dc64
//HFeebDxfRIJL16ag2zJCiXpfI1S/IxPFAPGFQgdwyew=
//hmac:-----HFeebDxfRIJL16ag2zJCiXpfI1S/IxPFAPGFQgdwyew=
