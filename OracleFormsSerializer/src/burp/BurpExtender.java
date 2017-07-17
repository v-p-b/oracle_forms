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
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import oracle.forms.engine.FormsDispatcher;
import oracle.forms.engine.FormsMessage;
import oracle.forms.engine.Message;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IScannerInsertionPointProvider
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
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {   
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("Oracle Forms Serializer loaded");
        
        // set our extension name
        callbacks.setExtensionName("Oracle Forms Serializer");
        
        //callbacks.registerProxyListener(this);
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
    
    private void printMessage(Message m){
    	for (int i=0;i<m.size();i++){
    		stdout.println("Property "+i+": "+m.getPropertyAt(i)+" Type: "+m.getPropertyTypeAt(i));
    		if (m.getValueAt(i)!=null)
    			stdout.println("--- Value: "+m.getValueAt(i).toString());
    		stdout.flush();
    	}
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
            return isRequest;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null || !isRequest)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
                PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
            	IRequestInfo rInfo=helpers.analyzeRequest(helpers.buildHttpService("dummyhost",1234,false),content);
        		byte[] body=Arrays.copyOfRange(content, rInfo.getBodyOffset(), content.length);
                String[] as=new String[256];
        		ByteArrayInputStream bis=new ByteArrayInputStream(body);
                DataInputStream dis=new DataInputStream(bis);
                int m_id=0;
                byte[] dummyRequest=helpers.buildHttpRequest(rInfo.getUrl()); // [TODO] POST plz
                Message m;
                try{
                    while((m=Message.readDetails(dis,as))!=null){
                        for (int i=0;i<m.size();i++){
                            if (m.getPropertyTypeAt(i)==1){
                                IParameter param=helpers.buildParameter(String.format("param_%d_%d",m_id,i), m.getValueAt(i).toString(), IParameter.PARAM_BODY);
                                dummyRequest=helpers.addParameter(dummyRequest,param);
                            }
                        }
                        m_id++;
                    }
                    txtInput.setText(dummyRequest);
                    txtInput.setEditable(true);
                }catch(EOFException eofe){
                    stdout.println("\nReached EOFin setMessage()");
                }catch(IOException e){
                    stdout.println("Message IOException");
                    e.printStackTrace(stdout);
                }
            }
            
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {

            PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

            IRequestInfo dummyRequest=helpers.analyzeRequest(txtInput.getText());
            HashMap<String,String> paramStrings=new HashMap<String,String>(); // Not necessarily optimal, but code is nicer...
            for (IParameter p: dummyRequest.getParameters()){
                paramStrings.put(p.getName(), p.getValue());
            }

            IRequestInfo rInfo=helpers.analyzeRequest(currentMessage);
            byte[] body=Arrays.copyOfRange(currentMessage, rInfo.getBodyOffset(), currentMessage.length);
            String[] as=new String[256];
            ByteArrayInputStream bis=new ByteArrayInputStream(body);
            DataInputStream dis=new DataInputStream(bis);
            int m_id=0;
            ByteArrayOutputStream baos=new ByteArrayOutputStream();
            DataOutputStream dos=new DataOutputStream(baos);
            Message m;
            try{
                while((m=Message.readDetails(dis,as))!=null){
                    for (int i=0;i<m.size();i++){
                        if (m.getPropertyTypeAt(i)==1){
                            String key=String.format("param_%d_%d",m_id,i);
                            if (paramStrings.containsKey(key)){
                                stdout.println("Setting value for "+key);
                                m.setValueAt(i, paramStrings.get(key));
                            }
                        }
                    }
                    m.writeDetails(new FormsDispatcher(), dos);
                    m_id++;
                }
                
            }catch(EOFException eofe){
                stdout.println("\nReached EOF in getMessage()");
            }catch(IOException e){
                stdout.println("Message IOException");
                e.printStackTrace(stdout);
            }
            try{
                dos.writeByte(-16);
                dos.writeByte(0x01);
                return helpers.buildHttpMessage(rInfo.getHeaders(), baos.toByteArray());
            }catch(IOException e){
                stdout.println("Message IOException - last bytes");
                e.printStackTrace(stdout);
                return null;
            }
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

		try{
			Message m;
			
			ByteArrayInputStream bis=new ByteArrayInputStream(body);
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
		}catch(EOFException eofe){
                stdout.println("\nReached EOF in getInsertionPoints()");
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
			DataOutputStream dos=new DataOutputStream(baos);
			
            try{
				for (int i=0;i<messages.size();i++){
					messages.get(i).writeDetails(new FormsDispatcher(), dos);
				}
			}catch(EOFException eofe){
                stdout.println("\nReached EOF in buildRequest");
            }catch(IOException ioe){
                stdout.println("IOExceltion while building scanner request!");
                ioe.printStackTrace(stdout);
				return null;
			}
            try{
                dos.writeByte(-16);
                dos.writeByte(0x01);
                dos.flush();
            }catch(IOException ioe){
                stdout.println("IOExceltion (last bytes) while building scanner request!");
                ioe.printStackTrace(stdout);
                return null;
            }
            byte[] res=baos.toByteArray();
            stdout.println("Scanner request built: "+byteArrayToHex(res));
            return helpers.buildHttpMessage(rInfo.getHeaders(), baos.toByteArray());
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
}