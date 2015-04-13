package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import oracle.forms.net.EncryptedInputStream;
import oracle.forms.net.EncryptedOutputStream;
import oracle.forms.engine.FormsDispatcher;
import oracle.forms.engine.FormsMessage;
import oracle.forms.engine.Message;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IProxyListener, IScannerInsertionPointProvider
{
	private PrintWriter stdout;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private byte[] clientKey=null;
	private byte[] serverKey=null;
	private byte[] rc4Key=new byte[5];
	private int[] reqSeedBuf=null;
	private int[] reqIndexVars=null;
	private int[] respSeedBuf=null;
	private int[] respIndexVars=null;
	private static String[] as=new String[256];
	private HashMap<String, OracleFormsStatefulRequest> formsRequests=new HashMap<String, OracleFormsStatefulRequest>();
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {   
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("Oracle Forms Tester loaded");
        
        // set our extension name
        callbacks.setExtensionName("Oracle Forms Tester");
        
        callbacks.registerProxyListener(this);
        callbacks.registerMessageEditorTabFactory(this);
        callbacks.registerScannerInsertionPointProvider(this);
    }
    
    public boolean gotKey(){
    	return this.clientKey!=null && this.serverKey!=null;
    }
    
    public static String byteArrayToHex(byte[] a) {
    	StringBuilder sb = new StringBuilder(a.length * 2);
    	for(byte b: a)
    		sb.append(String.format("%02x", b & 0xff));
    	return sb.toString();
    }
    
    @Override
    public synchronized void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
    	byte[] msg;

    	if (messageIsRequest){
			msg=message.getMessageInfo().getRequest();
    	}else{
    		msg=message.getMessageInfo().getResponse();
    	}
    	String strMsg=new String(msg); // TODO performance
    	
    	// Looking for the keys
    	if (!this.gotKey()){
    		if (messageIsRequest){
    			int idx=strMsg.indexOf("GDay");
    			if (idx!=-1){
    				stdout.println("Found GDay!");
    				this.clientKey=Arrays.copyOfRange(msg, idx+4, idx+8);
    				stdout.println("Found GDay! "+byteArrayToHex(this.clientKey));
    				return;
    			}
    		}else{
    			int idx=strMsg.indexOf("Mate");
    			if (idx!=-1){
    				this.serverKey=Arrays.copyOfRange(msg, idx+4, idx+8);
    				stdout.println("Found Mate! "+byteArrayToHex(this.serverKey));
    				ByteBuffer serverKeyBB=ByteBuffer.allocate(4);    				
    				serverKeyBB.order(ByteOrder.BIG_ENDIAN);
    				serverKeyBB.put(this.serverKey);
    				int serverKeyInt=serverKeyBB.getInt(0);
    				ByteBuffer clientKeyBB=ByteBuffer.allocate(4);
    				clientKeyBB.order(ByteOrder.BIG_ENDIAN);
    				clientKeyBB.put(this.clientKey);
    				int clientKeyInt=clientKeyBB.getInt(0);
    				rc4Key[0]=(byte)(clientKeyInt >> 8);
    				rc4Key[1]=(byte)(serverKeyInt >> 4);
    				rc4Key[2]=-82;
    				rc4Key[3]=(byte)(clientKeyInt >> 16);
    				rc4Key[4]=(byte)(serverKeyInt >> 12);
    				stdout.println("RC4 Key: "+byteArrayToHex(rc4Key));
    				return;
    			}
    		}
    	}else{
    		byte[] body=null;
    		try{
    			if(messageIsRequest){
    				stdout.println("Request:");
    				body=decryptRequest(msg);
    			}else{
    				stdout.println("Response:");   				
    				body=decryptResponse(msg);
    			}
    			
    			stdout.println("Body: "+body.length+" byte(s)");
    			if (body.length==0) return;
    			try{
    				Message m;
    				
    				ByteArrayInputStream bis=new ByteArrayInputStream(body);
    				DataInputStream dis=new DataInputStream(bis);
    				//int mCId=Message.createMessageCache();
    				while((m=Message.readDetails(dis,as))!=null){
    					printMessage(m);
    					stdout.println("Message OK");
    				}
    				//Message.destroyMessageCache(mCId);
    			}catch(IOException e){
    				stdout.println("Message IOException");
    				e.printStackTrace(stdout);
    			}catch(IllegalArgumentException iae){
    				stdout.println("Message IllegalArgumentException");
    				iae.printStackTrace(stdout);
    			}
    			stdout.println(byteArrayToHex(body));	
    			stdout.println("---");
    		}catch(IOException e){
    			stdout.println("Decryption failed!");
    		}
    	}
        /*stdout.println(
                (messageIsRequest ? "Proxy request to " : "Proxy response from ") +
                message.getMessageInfo().getHttpService());*/
    }
    
    private void printMessage(Message m){
    	for (int i=0;i<m.size();i++){
    		stdout.println("Property "+i+": "+m.getPropertyAt(i)+" Type: "+m.getPropertyTypeAt(i));
    		if (m.getValueAt(i)!=null)
    			stdout.println("--- Value: "+m.getValueAt(i).toString());
    		stdout.flush();
    	}
    }
    
    private byte[] decryptRequest(byte[] msg) throws IOException{
    	IRequestInfo rInfo=helpers.analyzeRequest(msg);
		byte[] body=Arrays.copyOfRange(msg, rInfo.getBodyOffset(), msg.length);
		stdout.println("Encrypted Request: "+byteArrayToHex(body));
		byte[] hash=null;
		try{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(body);
			stdout.println(byteArrayToHex(hash));
		}catch(NoSuchAlgorithmException nsae){
			stdout.println("Can't produce hash!");
		}
		EncryptedInputStream eis=new EncryptedInputStream(new ByteArrayInputStream(body),true);
		eis.setEncryptKey(rc4Key);
		if (this.reqSeedBuf!=null){
			eis.setSeedBuffer(this.reqSeedBuf);
			eis.setIndexVars(this.reqIndexVars);
		}
		byte[] out=new byte[body.length];				
		eis.read(out,0,body.length);
		OracleFormsStatefulRequest statefulMsg=new OracleFormsStatefulRequest();
		if (this.reqIndexVars!=null && this.reqSeedBuf!=null){
			statefulMsg.reqIndexVars=this.reqIndexVars.clone();
			statefulMsg.reqSeedBuf=this.reqSeedBuf.clone();
		}
		statefulMsg.plainBody=out.clone();
		this.reqIndexVars=eis.getIndexVars();
		this.reqSeedBuf=eis.getSeedBuffer();
		if (!formsRequests.containsKey(new String(hash)) && hash!=null){
			formsRequests.put(new String(hash), statefulMsg);
		}
		return out;
		
    }
    private byte[] decryptResponse(byte[] msg) throws IOException{
    	IResponseInfo rInfo=helpers.analyzeResponse(msg);
    	byte[] innerMsg=Arrays.copyOfRange(msg, rInfo.getBodyOffset(), msg.length);
    	rInfo=helpers.analyzeResponse(innerMsg);
		byte[] body=Arrays.copyOfRange(innerMsg, rInfo.getBodyOffset(), innerMsg.length);
		stdout.println("Encrypted Response: "+byteArrayToHex(body));
		if (rInfo.getStatedMimeType()!="app") return new byte[0];
		
		EncryptedInputStream eis=new EncryptedInputStream(new ByteArrayInputStream(body),true);
		eis.setEncryptKey(rc4Key);
		if (this.respSeedBuf!=null){
			eis.setSeedBuffer(this.respSeedBuf);
			eis.setIndexVars(this.respIndexVars);
		}
		byte[] out=new byte[body.length];				
		eis.read(out,0,body.length);
		this.respIndexVars=eis.getIndexVars();
		this.respSeedBuf=eis.getSeedBuffer();
		return out;
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new OracleFormsInputTab(controller, editable);
    }

    class OracleFormsInputTab implements IMessageEditorTab
    {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public OracleFormsInputTab(IMessageEditorController controller, boolean editable)
        {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override
        public String getTabCaption()
        {
            return "Oracle Forms";
        }

        @Override
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
            return isRequest && gotKey();
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
            	IRequestInfo rInfo=helpers.analyzeRequest(content);
        		byte[] body=Arrays.copyOfRange(content, rInfo.getBodyOffset(), content.length);
        		try{
        			MessageDigest digest = MessageDigest.getInstance("SHA-256");
        			byte[] hash = digest.digest(body);
        			txtInput.setText(formsRequests.get(new String(hash)).plainBody); 
        			txtInput.setEditable(false);
        		}catch(NoSuchAlgorithmException nsae){
        			txtInput.setText("Can't produce hash!".getBytes()); 
        			txtInput.setEditable(false);
        		}
            }
            
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {
            return currentMessage;
        }

        @Override
        public boolean isModified()
        {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
    }

	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(
			IHttpRequestResponse baseRequestResponse) {
		
		List<IScannerInsertionPoint> insertionPoints=new ArrayList<IScannerInsertionPoint>();
		byte[] msg=baseRequestResponse.getRequest();
		IRequestInfo rInfo=helpers.analyzeRequest(msg);
		byte[] body=Arrays.copyOfRange(msg, rInfo.getBodyOffset(), msg.length);
		OracleFormsStatefulRequest ofsr=null;
		try{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(body);
			ofsr=formsRequests.get(new String(hash));
		}catch(NoSuchAlgorithmException nsae){
			stdout.println("Can't produce hash!"); 
		}
		try{
			Message m;
			
			ByteArrayInputStream bis=new ByteArrayInputStream(ofsr.plainBody);
			DataInputStream dis=new DataInputStream(bis);
			ArrayList<Message> messages=new ArrayList<Message>();
			
			while((m=Message.readDetails(dis,as))!=null){
				stdout.println("Adding message as potential insertion point");
				messages.add(m);
			}
			for (int i=0;i<messages.size();i++){
				Message mi=messages.get(i);
		    	for (int j=0;j<mi.size();j++){
		    		if (mi.getPropertyTypeAt(j)==1){ // String property
		    			insertionPoints.add(new OracleFormsInsertionPoint(baseRequestResponse.getRequest(),messages, i, j));
		    		} 
		    	}
			}
		}catch(IOException e){
			stdout.println("Scanner Message IOException");
		}catch(IllegalArgumentException iae){
			stdout.println("Scanner Message IllegalArgumentException");
		}
		stdout.println("Supplied "+insertionPoints.size()+" insertion points");
		return insertionPoints;
	}
	class OracleFormsInsertionPoint implements IScannerInsertionPoint{
		private int propId=0;
		private int msgId=0;

		private ArrayList<Message> messages=new ArrayList<Message>();
		private byte[] baseRequest=null;
		
		public OracleFormsInsertionPoint(byte[] baseRequest,ArrayList<Message> messages, int msgId, int propId){
			this.messages=messages;
			this.msgId=msgId;
			this.propId=propId;
			this.baseRequest=baseRequest;
		}
		
		@Override
		public String getInsertionPointName() {
			return "Oracle Forms insertion point";
		}

		@Override
		public String getBaseValue() {
			return messages.get(msgId).getValueAt(propId).toString();
		}

		@Override
		public byte[] buildRequest(byte[] payload) {
			stdout.println("buildRequest called");
			IRequestInfo rInfo=helpers.analyzeRequest(this.baseRequest);
			messages.get(msgId).setValueAt(propId, new String(payload));
			ByteArrayOutputStream baos=new ByteArrayOutputStream();
			EncryptedOutputStream eos=new EncryptedOutputStream(baos);
			eos.setEncryptKey(rc4Key);
			eos.setIndexVars(reqIndexVars);
			eos.setSeedBuffer(reqSeedBuf);
			DataOutputStream dos=new DataOutputStream(eos);
			try{
				for (int i=0;i<messages.size();i++){
					messages.get(i).writeDetails(new FormsDispatcher(), dos);
				}
				dos.writeByte(-16);
				dos.writeByte(0x01);
				dos.flush();
				eos.flush();
				reqIndexVars=eos.getIndexVars().clone();
				reqSeedBuf=eos.getSeedBuffer().clone();
				byte[] res=baos.toByteArray();
				stdout.println("Scanner request built: "+byteArrayToHex(res));
				return helpers.buildHttpMessage(rInfo.getHeaders(), baos.toByteArray());
			}catch(IOException ioe){
				return null;
			}
			
		}

		@Override
		public int[] getPayloadOffsets(byte[] payload) {
			return null;
		}

		@Override
		public byte getInsertionPointType() {
			return INS_EXTENSION_PROVIDED;
		}
		
	}
	
	class OracleFormsStatefulRequest{
		public int[] reqSeedBuf=null;
		public int[] reqIndexVars=null;
		public byte[] plainBody=null;
	} 
}