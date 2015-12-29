package burp;

import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;

public class InsertionPoint implements IScannerInsertionPoint {
	
	private BurpExtender parent;
    private byte[] baseRequest;
    private String baseName;
    private String baseValue;
    private String value;

    InsertionPoint(BurpExtender newParent, byte[] baseRequest, String basename, String basevalue)
    {
    	this.parent = newParent;
        this.baseRequest = baseRequest;
        this.baseName = basename;
        //this.baseValue = basevalue;
        this.value = basevalue;
        this.baseValue = JSON.parseObject(basevalue).getString(basename);
        
    }

    // 
    // implement IScannerInsertionPoint
    //
    
    @Override
    public String getInsertionPointName()
    {
        return "AES Encrypted Input";
    }

    @Override
    public String getBaseValue()
    {
        return baseValue;
    }

    @Override
    public byte[] buildRequest(byte[] payload)
    {
    	String payloadPlain = parent.helpers.bytesToString(payload);
    	String payloadEncrypted = "";
    	String tmpAESKey = "0123456789abcdef";
    	parent.stdout.println("payloadPlain:" + payloadPlain);
    	parent.callbacks.issueAlert("payloadPlain:" + payloadPlain);
        try {
        	Map<String,String> map = JSON.parseObject(this.value, new TypeReference<Map<String, String>>(){}.getType());
        	map.put(this.baseName, getBaseValue() + payloadPlain );
        	String allPayloadPlain = JSON.toJSONString(map);
        	payloadEncrypted = parent.encryptRSAAndDES(allPayloadPlain, tmpAESKey, parent.key);
        	//payloadEncrypted = parent.encrypt(payloadPlain);
        } catch(Exception e) {
        	parent.callbacks.issueAlert(e.toString());
        }
        parent.stdout.println("Inserting " + payloadPlain + " [" + payloadEncrypted + "] in parameter " + baseName);
        //parent.callbacks.issueAlert("Inserting " + payloadPlain + " [" + payloadEncrypted + "] in parameter " + baseName);
        
        // TODO: Only URL parameters, must change to support POST parameters, cookies, etc.
        //return parent.helpers.updateParameter(baseRequest, parent.helpers.buildParameter(baseName, payloadEncrypted, IParameter.PARAM_URL));
        
        //"c" 表示要加密
        return parent.helpers.updateParameter(baseRequest, parent.helpers.buildParameter("c", payloadEncrypted, IParameter.PARAM_BODY));
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload)
    {
        // since the payload is being inserted into a serialized data structure, there aren't any offsets 
        // into the request where the payload literally appears
        return null;
    }

    @Override
    public byte getInsertionPointType()
    {
        return INS_EXTENSION_PROVIDED;
    }
}