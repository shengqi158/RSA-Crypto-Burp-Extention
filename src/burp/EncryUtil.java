package burp;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;

public class EncryUtil {
	private static final Logger log = Logger.getLogger(EncryUtil.class);
	/**
	 * 鐢熸垚RSA绛惧悕
	 */
	public static String handleRSA(TreeMap<String, Object> map,
			String privateKey) {
		StringBuffer sbuffer = new StringBuffer();
		for (Map.Entry<String, Object> entry : map.entrySet()) {
			sbuffer.append(entry.getValue());
		}
		String signTemp = sbuffer.toString();

		String sign = "";
		if (StringUtils.isNotEmpty(privateKey)) {
			sign = RSA.sign(signTemp, privateKey);
		}
		return sign;
	}

	/**
	 * 瀵规槗瀹濇敮浠樿繑鍥炵殑缁撴灉杩涜楠岀
	 * 
	 * @param data
	 *            鏄撳疂鏀粯杩斿洖鐨勪笟鍔℃暟鎹瘑鏂�	 * @param encrypt_key
	 *            鏄撳疂鏀粯杩斿洖鐨勫ybAesKey鍔犲瘑鍚庣殑瀵嗘枃
	 * @param yibaoPublickKey
	 *            鏄撳疂鏀粯鎻愪緵鐨勫叕閽�	 * @param merchantPrivateKey
	 *            鍟嗘埛鑷繁鐨勭閽�	 * @return 楠岀鏄惁閫氳繃
	 * @throws Exception
	 */
	public static boolean checkDecryptAndSign(String data, String encrypt_key,
			String yibaoPublickKey, String merchantPrivateKey) throws Exception {

		/** 1.浣跨敤YBprivatekey瑙ｅ紑aesEncrypt銆�*/
		String AESKey = "";
		try {
			AESKey = RSA.decrypt(encrypt_key, merchantPrivateKey);
		} catch (Exception e) {
			e.printStackTrace();
			/** AES瀵嗛挜瑙ｅ瘑澶辫触 */
			log.error(e.getMessage(), e);
			return false;
		}

		/** 2.鐢╝eskey瑙ｅ紑data銆傚彇寰梔ata鏄庢枃 */
		String realData = AES.decryptFromBase64(data, AESKey);
		
		TreeMap<String, String> map = JSON.parseObject(realData,
				new TypeReference<TreeMap<String, String>>() {
				});

		/** 3.鍙栧緱data鏄庢枃sign銆�*/
		String sign = StringUtils.trimToEmpty(map.get("sign"));

		/** 4.瀵筸ap涓殑鍊艰繘琛岄獙璇�*/
		StringBuffer signData = new StringBuffer();
		Iterator<Entry<String, String>> iter = map.entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String, String> entry = iter.next();

			/** 鎶妔ign鍙傛暟闅旇繃鍘�*/
			if (StringUtils.equals((String) entry.getKey(), "sign")) {
				continue;
			}
			signData.append(entry.getValue() == null ? "" : entry.getValue());
		}
		
		/** 5. result涓簍rue鏃惰〃鏄庨獙绛鹃�杩�*/
		boolean result = RSA.checkSign(signData.toString(), sign,
				yibaoPublickKey);

		return result;
	}

	/**
	 * 鐢熸垚hmac
	 */
	public static String handleHmac(TreeMap<String, String> map, String hmacKey) {
		StringBuffer sbuffer = new StringBuffer();
		for (Map.Entry<String, String> entry : map.entrySet()) {
			sbuffer.append(entry.getValue());
		}
		String hmacTemp = sbuffer.toString();

		String hmac = "";
		if (StringUtils.isNotEmpty(hmacKey)) {
			hmac = Digest.hmacSHASign(hmacTemp, hmacKey, Digest.ENCODE);
		}
		return hmac;
	}
}
