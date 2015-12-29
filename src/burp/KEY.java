
package burp;


import java.io.ByteArrayOutputStream;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;


public class KEY {
    public String privateKey = "";
    public String publicKey = "";

    /**
     * 获取私钥别名等信息
     */
    public KEY(String fileName, String privKeyPwdString,  String keyStroeType) {
        //String privKeyPswdString = "1234567890abc";
        String privKeyPswdString = privKeyPwdString;

        String keyAlias = null;
        try {
            //KeyStore keyStore = KeyStore.getInstance("PKCS12");
        	KeyStore keyStore = KeyStore.getInstance("PKCS12");
            // KeyStore keyStore = KeyStore.getInstance("RSA");
            //FileInputStream fileInputStream = new FileInputStream("private_key.p12");
            FileInputStream fileInputStream = new FileInputStream(fileName);

            char[] nPassword = null;
            if ((privKeyPswdString == null) || privKeyPswdString.trim().equals("")) {
                nPassword = null;
            } else {
                nPassword = privKeyPswdString.toCharArray();
            }
            keyStore.load(fileInputStream, nPassword);
            fileInputStream.close();
            System.out.println("keyType:"+keyStore.getType());
            Enumeration<String> enumeration = keyStore.aliases();
            if (enumeration.hasMoreElements()) {
                keyAlias = (String) enumeration.nextElement();
                System.out.print("keyAlias:" + keyAlias);
            }
            System.out.println("is entry:" + keyStore.isKeyEntry(keyAlias));
            PrivateKey prikey = (PrivateKey) keyStore.getKey(keyAlias, nPassword);
            Certificate cert = keyStore.getCertificate(keyAlias);
            PublicKey pubkey = cert.getPublicKey();
            //publicKey = Base64.encode(publicKey.getBytes().toString());
            //privateKey = Base64.encode(prikey.getEncoded().toString());
            //publicKey = Base64.encode(pubkey.getEncoded().toString());
            //privateKey = Base64.encode(new String(prikey.getEncoded()));
            privateKey = new String(Base64.encodeBase64(prikey.getEncoded()));
            System.out.println("private key0:" + privateKey);
            
            
            //privateKey = Base64.encode(prikey.getEncoded());
  
            //publicKey = Base64.encode(new String(pubkey.getEncoded()));
            publicKey = new String(Base64.encodeBase64(pubkey.getEncoded()));
            //privateKey = Base64.encodeToString(prikey.getEncoded());
            //publicKey = this.getPublicKey();
            System.out.println("cert class = " + cert.getClass().getName());
            System.out.println("cert = " + cert);
            System.out.println("public key direct:" + publicKey);
            System.out.println("public key :" + publicKey);
            System.out.println("private key:" + privateKey);
            
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    /**
     * 读取公钥cer
     * 
     * @param path .cer文件的路径 如：c:/abc.cer
     * @return base64后的公钥串
     * @throws IOException
     * @throws CertificateException
     */
    public static String getPublicKey() throws IOException, CertificateException {
        InputStream inStream = new FileInputStream("D:\\public_key.cer");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;
        while ((ch = inStream.read()) != -1) {
            out.write(ch);
        }
        inStream.close();
        byte[] result = out.toByteArray();
        return Base64.encode(result.toString());
        //return Base64.encodeToString(result, Base64.DEFAULT);
    }
}
