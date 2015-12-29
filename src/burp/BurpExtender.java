package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.awt.*;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.JTextArea;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JButton;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;
import java.io.File;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider, ITab, IHttpListener {
    
	// IExtensionHelpers helpers;
	public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    
    public PrintWriter stdout;
    public PrintWriter stderr;
    
    public KEY key;

    // GUI Components
    private JPanel panel;
    
    public final String TAB_NAME = "RSA Config";
    private JTextField parameterRSAFile;
    private JTextField parameterRSAPasswd;
    private JLabel lblDescription;
    private JComboBox comboAESMode;
    private JLabel lbl3;
    private JCheckBox chckbxNewCheckBox;
    private JPanel panel_1;
    private JButton btnNewButton;
    private JTextArea textAreaPlaintext;
    private JTextArea textAreaCiphertext;
    private JButton btnNewButton_1;
    private JLabel lblPlaintext;
    private JLabel lblCiphertext;
    

    public IntruderPayloadProcessor payloadEncryptor;
    public IntruderPayloadProcessor payloadDecryptor;
    
    public Boolean isURLEncoded;
    
    private JLabel lbl4;
    private JComboBox comboEncoding;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
    	this.callbacks = callbacks;
    	
    	
    	// obtain an extension helpers object
        helpers = callbacks.getHelpers();
        

        // set our extension name
        callbacks.setExtensionName("RSA Crypto v1.0");
      
        // Register payload encoders
        payloadEncryptor = new IntruderPayloadProcessor(this, 1);
        callbacks.registerIntruderPayloadProcessor(payloadEncryptor);
        
        payloadDecryptor = new IntruderPayloadProcessor(this, 0);
        callbacks.registerIntruderPayloadProcessor(payloadDecryptor);
        
        // register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(this);
        
        isURLEncoded = false;

        // Create UI
        this.addMenuTab();
        //this.setKey(parameterRSAFile.getText(), parameterRSAPasswd.getText(), "PCKS12");
        //Add log
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);
        stdout.println("RSA loaded");
    }
    

    /**
     * @wbp.parser.entryPoint
     * 
     * This code was built using Eclipse's WindowBuilder
     */
    public void buildUI() {
    	panel = new JPanel();
    	GridBagLayout gbl_panel = new GridBagLayout();
    	gbl_panel.columnWidths = new int[]{197, 400, 0};
    	gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0};
    	gbl_panel.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
    	gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
    	panel.setLayout(gbl_panel);
    	
    	lblDescription = new JLabel("<html><b>BURP RSA Manipulation functions v1.0</b>\r\n<br>\r\n<br>\r\nweibo: http://weibo.com/1900013681\r\n<br>\r\ngithub: github.com/shengqi158\r\n<br>\r\n<br>\r\nRSA p12 filepath is the filepath of your RSA，\r\n<ul>\r\n  <li>RSA and AES Encrypt / Decrypt Payload Encoder</li>\r\n  <li>Scanner Insertion Point Provider: attempts to insert payloads inside encrypted insertion points</li>\r\n</ul>\r\n\r\n</html>");
    	lblDescription.setHorizontalAlignment(SwingConstants.LEFT);
    	lblDescription.setVerticalAlignment(SwingConstants.TOP);
    	GridBagConstraints gbc_lblDescription = new GridBagConstraints();
    	gbc_lblDescription.fill = GridBagConstraints.HORIZONTAL;
    	gbc_lblDescription.insets = new Insets(20, 20, 20, 20);
    	gbc_lblDescription.gridx = 1;
    	gbc_lblDescription.gridy = 0;
    	panel.add(lblDescription, gbc_lblDescription);
    	
    	JLabel lbl1 = new JLabel("RSA p12 file path:");
    	lbl1.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl1 = new GridBagConstraints();
    	gbc_lbl1.anchor = GridBagConstraints.EAST;
    	gbc_lbl1.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl1.gridx = 0;
    	gbc_lbl1.gridy = 1;
    	panel.add(lbl1, gbc_lbl1);
    	
    	parameterRSAFile = new JTextField();
    	parameterRSAFile.setText("D:\\private_key.p12");
    	GridBagConstraints gbc_parameterRSAFile = new GridBagConstraints();
    	gbc_parameterRSAFile.insets = new Insets(0, 0, 5, 0);
    	gbc_parameterRSAFile.fill = GridBagConstraints.HORIZONTAL;
    	gbc_parameterRSAFile.gridx = 1;
    	gbc_parameterRSAFile.gridy = 1;
    	panel.add(parameterRSAFile, gbc_parameterRSAFile);
    	parameterRSAFile.setColumns(10);
    	
    	JLabel lbl2 = new JLabel("RSA Password:");
    	lbl2.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl2 = new GridBagConstraints();
    	gbc_lbl2.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl2.anchor = GridBagConstraints.EAST;
    	gbc_lbl2.gridx = 0;
    	gbc_lbl2.gridy = 2;
    	panel.add(lbl2, gbc_lbl2);
    	
    	parameterRSAPasswd = new JTextField();
    	parameterRSAPasswd.setText("1234567890abc");
    	parameterRSAPasswd.setColumns(10);
    	GridBagConstraints gbc_parameterRSAPasswd = new GridBagConstraints();
    	gbc_parameterRSAPasswd.insets = new Insets(0, 0, 5, 0);
    	gbc_parameterRSAPasswd.fill = GridBagConstraints.HORIZONTAL;
    	gbc_parameterRSAPasswd.gridx = 1;
    	gbc_parameterRSAPasswd.gridy = 2;
    	panel.add(parameterRSAPasswd, gbc_parameterRSAPasswd);
    	
    	chckbxNewCheckBox = new JCheckBox("IV block in Ciphertext (not yet working)");
    	chckbxNewCheckBox.setEnabled(false);
    	GridBagConstraints gbc_chckbxNewCheckBox = new GridBagConstraints();
    	gbc_chckbxNewCheckBox.fill = GridBagConstraints.HORIZONTAL;
    	gbc_chckbxNewCheckBox.insets = new Insets(0, 0, 5, 0);
    	gbc_chckbxNewCheckBox.gridx = 1;
    	gbc_chckbxNewCheckBox.gridy = 3;
    	panel.add(chckbxNewCheckBox, gbc_chckbxNewCheckBox);
    	
    	lbl4 = new JLabel("Ciphertext encoding:");
    	lbl4.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl4 = new GridBagConstraints();
    	gbc_lbl4.anchor = GridBagConstraints.EAST;
    	gbc_lbl4.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl4.gridx = 0;
    	gbc_lbl4.gridy = 4;
    	//panel.add(lbl4, gbc_lbl4);
    	
    	comboEncoding = new JComboBox();
    	comboEncoding.setModel(new DefaultComboBoxModel(new String[] {"Base 64", "ASCII Hex"}));
    	comboEncoding.setSelectedIndex(0);
    	GridBagConstraints gbc_comboEncoding = new GridBagConstraints();
    	gbc_comboEncoding.insets = new Insets(0, 0, 5, 0);
    	gbc_comboEncoding.fill = GridBagConstraints.HORIZONTAL;
    	gbc_comboEncoding.gridx = 1;
    	gbc_comboEncoding.gridy = 4;
    	//panel.add(comboEncoding, gbc_comboEncoding);
    	
    	lbl3 = new JLabel("AES Mode:");
    	lbl3.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl3 = new GridBagConstraints();
    	gbc_lbl3.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl3.anchor = GridBagConstraints.EAST;
    	gbc_lbl3.gridx = 0;
    	gbc_lbl3.gridy = 5;
    	//panel.add(lbl3, gbc_lbl3);
    	
    	comboAESMode = new JComboBox();
    	comboAESMode.addPropertyChangeListener(new PropertyChangeListener() {
    		public void propertyChange(PropertyChangeEvent arg0) {
    			String cmode = (String)comboAESMode.getSelectedItem();
    			if (cmode.contains("CBC")) {
    				parameterRSAPasswd.setEditable(true);
    			} else {
    				parameterRSAPasswd.setEditable(false);
    			}
    		}
    	});
    	comboAESMode.setModel(new DefaultComboBoxModel(new String[] {"AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding"}));
    	comboAESMode.setSelectedIndex(1);
    	GridBagConstraints gbc_comboAESMode = new GridBagConstraints();
    	gbc_comboAESMode.insets = new Insets(0, 0, 5, 0);
    	gbc_comboAESMode.fill = GridBagConstraints.HORIZONTAL;
    	gbc_comboAESMode.gridx = 1;
    	gbc_comboAESMode.gridy = 5;
    	//panel.add(comboAESMode, gbc_comboAESMode);
    	
    	panel_1 = new JPanel();
    	GridBagConstraints gbc_panel_1 = new GridBagConstraints();
    	gbc_panel_1.gridwidth = 2;
    	gbc_panel_1.fill = GridBagConstraints.BOTH;
    	gbc_panel_1.gridx = 0;
    	gbc_panel_1.gridy = 6;
    	panel.add(panel_1, gbc_panel_1);
    	GridBagLayout gbl_panel_1 = new GridBagLayout();
    	gbl_panel_1.columnWidths = new int[]{0, 0, 0, 0};
    	gbl_panel_1.rowHeights = new int[]{0, 0, 0, 0};
    	gbl_panel_1.columnWeights = new double[]{1.0, 0.0, 1.0, Double.MIN_VALUE};
    	gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
    	panel_1.setLayout(gbl_panel_1);
    	
    	lblPlaintext = new JLabel("Plaintext");
    	lblPlaintext.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lblPlaintext = new GridBagConstraints();
    	gbc_lblPlaintext.insets = new Insets(0, 0, 5, 5);
    	gbc_lblPlaintext.gridx = 0;
    	gbc_lblPlaintext.gridy = 0;
    	panel_1.add(lblPlaintext, gbc_lblPlaintext);
    	
    	lblCiphertext = new JLabel("Ciphertext");
    	lblCiphertext.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lblCiphertext = new GridBagConstraints();
    	gbc_lblCiphertext.insets = new Insets(0, 0, 5, 0);
    	gbc_lblCiphertext.gridx = 2;
    	gbc_lblCiphertext.gridy = 0;
    	panel_1.add(lblCiphertext, gbc_lblCiphertext);
    	
    	textAreaPlaintext = new JTextArea();
    	textAreaPlaintext.setLineWrap(true);
    	GridBagConstraints gbc_textAreaPlaintext = new GridBagConstraints();
    	gbc_textAreaPlaintext.gridheight = 2;
    	gbc_textAreaPlaintext.insets = new Insets(0, 0, 0, 5);
    	gbc_textAreaPlaintext.fill = GridBagConstraints.BOTH;
    	gbc_textAreaPlaintext.gridx = 0;
    	gbc_textAreaPlaintext.gridy = 1;
    	panel_1.add(textAreaPlaintext, gbc_textAreaPlaintext);
    	
    	/*
    	 * set key
    	 */
    	this.setKey(parameterRSAFile.getText(), parameterRSAPasswd.getText(), "PCKS12");
    	
    	
    	btnNewButton = new JButton("Encrypt ->");
    	btnNewButton.addActionListener(new ActionListener() {
    		public void actionPerformed(ActionEvent arg0) {		
    	        try {
    	        	String tmpAESKey = "0123456789abcdef";
    	        	textAreaCiphertext.setText((textAreaPlaintext.getText()));
    	        	textAreaCiphertext.setText(encryptRSAAndDES(textAreaPlaintext.getText(), tmpAESKey, key));
    	        } catch(Exception e) {
    	        	callbacks.issueAlert(e.toString());
    	        }
    			
    		}
    	});
    	GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
    	gbc_btnNewButton.insets = new Insets(0, 0, 5, 5);
    	gbc_btnNewButton.gridx = 1;
    	gbc_btnNewButton.gridy = 1;
    	panel_1.add(btnNewButton, gbc_btnNewButton);
    	
    	textAreaCiphertext = new JTextArea();
    	textAreaCiphertext.setLineWrap(true);
    	GridBagConstraints gbc_textAreaCiphertext = new GridBagConstraints();
    	gbc_textAreaCiphertext.gridheight = 2;
    	gbc_textAreaCiphertext.fill = GridBagConstraints.BOTH;
    	gbc_textAreaCiphertext.gridx = 2;
    	gbc_textAreaCiphertext.gridy = 1;
    	panel_1.add(textAreaCiphertext, gbc_textAreaCiphertext);
    	
    	btnNewButton_1 = new JButton("<- Decrypt");
    	btnNewButton_1.addActionListener(new ActionListener() {
    		public void actionPerformed(ActionEvent arg0) {
    	        try {
    	        	//textAreaPlaintext.setText(decrypt(textAreaCiphertext.getText()));
    	        	EncryptBean encryptBean = JSON.parseObject(textAreaCiphertext.getText(), EncryptBean.class);
    	        	textAreaPlaintext.setText(decryptRSAAndDES(key, encryptBean));
    	        } catch(Exception e) {
    	        	callbacks.issueAlert(e.toString());
    	        }
    		}
    	});
    	btnNewButton_1.setVerticalAlignment(SwingConstants.TOP);
    	GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
    	gbc_btnNewButton_1.anchor = GridBagConstraints.NORTH;
    	gbc_btnNewButton_1.insets = new Insets(0, 0, 0, 5);
    	gbc_btnNewButton_1.gridx = 1;
    	gbc_btnNewButton_1.gridy = 2;
    	panel_1.add(btnNewButton_1, gbc_btnNewButton_1);
    }
 
    public void addMenuTab() {
        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
            	buildUI();
            	callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    
    @Override
    public String getTabCaption()
    {
        return "RSA Crypto";
    }

    @Override
    public Component getUiComponent()
    {
		return panel;
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
	public static String byteArrayToHexString(byte[] b) {
		int len = b.length;
		String data = new String();
		for (int i = 0; i < len; i++){
			data += Integer.toHexString((b[i] >> 4) & 0xf);
			data += Integer.toHexString(b[i] & 0xf);
		}
		return data;
	}
	
	public void setKey(String fileName, String passwd, String keyStoreType){
		
		File f = new File(fileName);
		if (!f.exists()){
			stderr.println("RSA FILE is not exists!!!!");
			callbacks.issueAlert("RSA FILE is not exists");
		}
		stdout.println("filename:" + fileName + "password:" + passwd + "keyStoreType:" + keyStoreType);
		this.key = new KEY(fileName, passwd, keyStoreType);
	}
    
    //
    // implement IScannerInsertionPointProvider
    //
    
    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
    	// insertion points to return
        List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();
        
        // retrieve request parameters
    	IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());
    	List<IParameter> requestParams = requestInfo.getParameters();
    	
    	//callbacks.issueAlert("Searching for RSA encrypted data in request...");
    	
    	for (IParameter parameter : requestParams) {
    		String value = parameter.getValue();
    		value = helpers.urlDecode(value).trim();
    		EncryptBean encryptBean = new EncryptBean();
    		
    		//callbacks.issueAlert("Will scan  data at parameter " + parameter + " with value encrypted " + value);
    		stdout.println("before decrypted name:"+parameter.getName() + "value:"+value);
    		
    		
    		if (parameter.getName().trim().equals("c")){//参数中含有c参数表示要加密的内容
    			encryptBean = JSON.parseObject(value, EncryptBean.class);
    			
        		stdout.println("private key: " + key.privateKey + " public key " + key.publicKey);
        		stdout.println("encryptKey:"+encryptBean.encryptKey + "data: " + encryptBean.data);
        		try {
					value = decryptRSAAndDES(key, encryptBean);
					stdout.println("after decrypted:Will scan  data at parameter " + parameter + " with value decrypted " + value);
					
				} catch (Exception e) {
					// TODO Auto-generated catch block
					stderr.println(e.getMessage());
					e.printStackTrace();
				}
        		
        		if (value.isEmpty()) continue;
    		
        		try {
        			//String basevalue = decrypt(value);
        			String basename = parameter.getName();
        			//insertionPoints.add(new InsertionPoint(this, baseRequestResponse.getRequest(), basename, value));
        			//stdout.println("after addinsert:Will scan AES encrypted data at parameter " + basename + " with value " + value);
        			JSONObject jsonObj = JSON.parseObject(value);
            	
        			String basevalue = "";
        			for(Map.Entry<String, Object> entry: jsonObj.entrySet()){
        				basename = entry.getKey();
        				basevalue = entry.getValue().toString();
        				//在这里传入总的value值以便在InsertionPoint进行分解，构造加密后的request请求，构造InsertionPoint时传入的value为总的value值
        				insertionPoints.add(0,new InsertionPoint(this, baseRequestResponse.getRequest(), basename, value));
        				stdout.println("in for:Will scan AES encrypted data at parameter " + basename + " with value " + value);
        			}
        			//callbacks.issueAlert("Will scan AES encrypted data at parameter " + basename + " with value " + basevalue);
        			// Add insertion point
        			//insertionPoints.add(new InsertionPoint(this, baseRequestResponse.getRequest(), basename, basevalue));
        		} catch(Exception e) {
        		}

    		}

    	}
    	
        return insertionPoints;
    }


    public String encrypt(String plainText) throws Exception {
    	
    	byte[] keyValue= hexStringToByteArray(parameterRSAFile.getText());
    	Key skeySpec = new SecretKeySpec(keyValue, "AES");
    	
    	byte[] iv = hexStringToByteArray(parameterRSAPasswd.getText());
    	IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String cmode = (String)comboAESMode.getSelectedItem();
        
        Cipher cipher = Cipher.getInstance((String)comboAESMode.getSelectedItem());
        if (cmode.contains("CBC")) {
        	cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        } else {
        	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        }

        byte[] encVal = cipher.doFinal(plainText.getBytes());

        // This wont work for http requests either output ascii hex or url encoded values
        String encryptedValue = new String(encVal, "UTF-8");
        
        switch (comboEncoding.getSelectedItem().toString()) {
    		case "Base 64":
    			encryptedValue = helpers.base64Encode(encVal);
    			break;
    		case "ASCII Hex":
    			encryptedValue = byteArrayToHexString(encVal);
    			break;
        }
        
        return encryptedValue;
    }
    
    public String decrypt(String ciphertext) throws Exception {

    	byte[] keyValue= hexStringToByteArray(parameterRSAFile.getText());
    	Key skeySpec = new SecretKeySpec(keyValue, "AES");
    	byte[] iv = hexStringToByteArray(parameterRSAPasswd.getText());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        String cmode = (String)comboAESMode.getSelectedItem();
    	
        Cipher cipher = Cipher.getInstance(cmode);
        if (cmode.contains("CBC")) {
        	cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        } else {
        	cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        }
        
        byte [] cipherbytes = ciphertext.getBytes();
        
        switch (comboEncoding.getSelectedItem().toString()) {
        	case "Base 64":
        		cipherbytes = helpers.base64Decode(ciphertext);
        		break;
    		case "ASCII Hex":
    			cipherbytes = hexStringToByteArray(ciphertext);
    			break;
        }
        
        byte[] original = cipher.doFinal(cipherbytes);
        return new String(original);
    	
    }
    

    
    public String decryptRSAAndDES(KEY key, EncryptBean encryptBean) throws Exception {
    	//解密
    	String decryptedString = "";
    	String aesKey = "";
    	try{
    		//String privateKey = new String(Base64.decodeBase64(key.privateKey.getBytes()));
			//String aesKey = RSA.decrypt(encryptBean.encryptKey, privateKey);
			aesKey = RSA.decrypt(encryptBean.encryptKey, key.privateKey);
			System.out.println("aesKey: " + aesKey);
			//this.stdout.println("aeskey:" + aesKey);
			//this.stdout.println("encrypteBean.data:" + encryptBean.data);
			//stdout.println("aesKey:" + aesKey);

			decryptedString = AES.decryptFromBase64(encryptBean.data, aesKey);
    		
    	}catch(Exception e){
    		e.printStackTrace();
    		stdout.println(e.getMessage());
    		e.printStackTrace(stdout);
    	}
    	return decryptedString;
    }
    public  String encryptRSAAndDES(String content, String aesKey, KEY key){
    	String bean_json = "";
    	try{
    		String data = AES.encryptToBase64(content, aesKey);
    		String encryptKey = RSA.encrypt(aesKey, key.publicKey);
    		EncryptBean bean = new EncryptBean();
    		bean.data = data;
    		bean.encryptKey = encryptKey;
    		bean_json = JSON.toJSONString(bean);
    		
    	}catch(Exception e){
    		e.printStackTrace(stdout);
    	}
		return bean_json;
    }

    //public String getParams(){}
    public static void main(String[] args) throws Exception{
    	String test = "c=%7B%22data%22%3A%22PT%2FrD2jvNybPL%2FRgkT3%2Fxz0wq4ubwe%2BLHJboW3oe4sd9VNRyis778rV6yGYCcri09sQt0VoDd05GXe65IJUP31Ok7VsXQwm7cUzqDU6Yb%2BAIbQU4FfZdknrB7jBHfcu3KpnZBCACaG4qYZACATwZB4sK1WnaZS0hmtBcppqzFZtX%2Biu6qWYsWDNwtAfOTio95QZkHFJKugHdoECU6BP2vC%2FyfOXaHusQmC0RIE8csO4mdaggE8XVUwXUbKHgT462%22%2C%22encryptKey%22%3A%22tL11%2FnPKFNrWSTr4mSzHSKaiF2cWgnUE6X6tnNvmPzKYnJYVJ6QrIUdDAf7S3FywffqZXJ37BpfByT8jF8fQ8WsDkRCWM8Lcsn3tXFGtDQcdB4Wl%2FeWePzty1Q0JPgeBT5dHcLWr9iX1nB%2B5MUrAvitnbqXofAodNIaYe6exP6c%5Cu003d%22%7D&";
    	
    	//String test = "c={"data":"PT/rD2jvNybPL/RgkT3/xz0wq4ubwe+LHJboW3oe4sd9VNRyis778rV6yGYCcri09sQt0VoDd05GXe65IJUP31Ok7VsXQwm7cUzqDU6Yb+AIbQU4FfZdknrB7jBHfcu3KpnZBCACaG4qYZACATwZB4sK1WnaZS0hmtBcppqzFZtX+iu6qWYsWDNwtAfOTio95QZkHFJKugHdoECU6BP2vC/yfOXaHusQmC0RIE8csO4mdaggE8XVUwXUbKHgT462","encryptKey":"tL11/nPKFNrWSTr4mSzHSKaiF2cWgnUE6X6tnNvmPzKYnJYVJ6QrIUdDAf7S3FywffqZXJ37BpfByT8jF8fQ8WsDkRCWM8Lcsn3tXFGtDQcdB4Wl/eWePzty1Q0JPgeBT5dHcLWr9iX1nB+5MUrAvitnbqXofAodNIaYe6exP6c\u003d"}";
    	String privKeyPwdString = "1234567890abc";
    	String fileName = "D:\\private_key.p12";
    	String keyStoreType = "PKCS12";
    	test =  java.net.URLDecoder.decode(test, "UTF-8");
    	
    	System.out.println("url decoded:" + test);
    	KEY key = new KEY(fileName, privKeyPwdString, keyStoreType);
    	System.out.println("privateKey:"+key.privateKey+"\r\npublicKey:" + key.publicKey);
    	BurpExtender b = new BurpExtender(); 
    	String encStr = b.encryptRSAAndDES("contentcontent","1234567891234567",key);
    	//String encStr = encryptRSAAndDES("contentcontent","1234567891234567",key);
    	System.out.println("encStr:"+ encStr);
    	EncryptBean encryptBean = new EncryptBean();
    	encryptBean = JSON.parseObject(test.substring(2,test.length()-1), EncryptBean.class);
    	String decrypted_str = b.decryptRSAAndDES(key, encryptBean);
    	//String decrypted_str = decryptRSAAndDES(encStr,key);
    	System.out.print("c".equals("c"));

    	System.out.println(decrypted_str);
    }


	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest,
			IHttpRequestResponse messageInfo) {
		//判断是response
		if(!messageIsRequest){
			stdout.println("in processhttpmessage");
			callbacks.issueAlert("in processhttpmessage!!!");
			//监听scanner和intruder工具
			if(toolFlag == callbacks.TOOL_SCANNER || toolFlag == callbacks.TOOL_INTRUDER){
				IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
				int offset = responseInfo.getBodyOffset();
				String responseStr = helpers.bytesToString(messageInfo.getResponse()).substring(offset);
				stdout.println("responseStr:" + responseStr);
				callbacks.issueAlert("responseStr:" + responseStr);
				EncryptBean encryptBean = new EncryptBean();
				try{
					encryptBean = JSON.parseObject(responseStr,EncryptBean.class);
					String decryptStr = decryptRSAAndDES(this.key, encryptBean);
					messageInfo.setResponse(helpers.buildHttpMessage(responseInfo.getHeaders(), helpers.stringToBytes(decryptStr)));
				}catch(Exception e){
					e.printStackTrace(stdout);
				}
				
			}
			
		}
		// TODO Auto-generated method stub
		
	}
}
