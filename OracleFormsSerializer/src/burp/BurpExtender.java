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

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IScannerInsertionPointProvider, IHttpListener
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
        callbacks.registerHttpListener(this);
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
    
    private String messageToString(Message m){
        StringBuilder ret=new StringBuilder();
        /*if (m.isDeltaMessage()){
            ret.append("Delta message, Delta Index: "+m.getDeltaIndex()+"\n");    
        }*/
        
        for (int i=0;i<m.size();i++){
            ret.append("Property "+i+": "+m.getPropertyAt(i)+" Type: "+m.getPropertyTypeAt(i)+"\n");
            if (m.getValueAt(i)==null){
                ret.append("--- Value: null\n");
            }else{
                ret.append("--- Value: "+ m.getValueAt(i).toString()+"\n");
                if (m.getValueAt(i) instanceof Message){
                    ret.append(">>> Begin recursive print\n");
                    ret.append(messageToString((Message)m.getValueAt(i)));
                    ret.append("\n<<< End recursive print\n");
                }
            }
        }
        return ret.toString();
    }
    

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        if(!messageIsRequest){  // We don't care if it's not a request
            return;
        }

        byte[] msg=messageInfo.getRequest();
        IRequestInfo rInfo=helpers.analyzeRequest(messageInfo);

        if (rInfo.getUrl().toString().indexOf("/lservlet") == -1 || rInfo.getMethod() != "POST"){ // We don't care if it's not a POST for Forms
            return; 
        }

        byte[] handshakeBody=Arrays.copyOfRange(msg, rInfo.getBodyOffset(), rInfo.getBodyOffset() + 4);
        if (Arrays.equals(handshakeBody, new byte[] {0x47, 0x44, 0x61, 0x79} )){ // We don't care about the intial handshake
            stdout.println("Ignoring handshake in HTTP Listener");
            return;
        }

        byte[] body=Arrays.copyOfRange(msg, rInfo.getBodyOffset(), msg.length);
        
        if (body.length == 0){ // We don't care about empty bodies
            return;
        }

        String[] as=new String[256];
        ByteArrayInputStream bis=new ByteArrayInputStream(body);
        DataInputStream dis=new DataInputStream(bis);
        Message m;

        try{
            if (body[body.length-2] != (byte)0xf0){
                throw new IllegalArgumentException("Illegal close Message detected!");
            }
            while((m=Message.readDetails(dis,as))!=null){}
        }catch(Exception e){
            stdout.println("Caught exception while decoding Forms HTTP request! Redirecting to localhost...");
            stdout.println(e.getMessage());
            messageInfo.setHttpService(helpers.buildHttpService("127.0.0.1",65535,false));
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
            return true;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
                return;
            }


            IRequestInfo rInfo=helpers.analyzeRequest(helpers.buildHttpService("dummyhost",1234,false),content);
            byte[] body=Arrays.copyOfRange(content, rInfo.getBodyOffset(), content.length);
            String[] as=new String[256];
            ByteArrayInputStream bis=new ByteArrayInputStream(body);
            DataInputStream dis=new DataInputStream(bis);
            PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
            Message m;
            if(!isRequest){
                try{
                    StringBuilder sb=new StringBuilder();
                    
                    while((m=Message.readDetails(dis,as))!=null){
                        sb.append(messageToString(m));
                        sb.append("\n+++ Message +++\n");
                    }
                    txtInput.setText(sb.toString().getBytes());
                    txtInput.setEditable(false);
                }catch(EOFException eofe){
                    stdout.println("\nReached EOFin setMessage()");
                }catch(IOException e){
                    stdout.println("Message IOException");
                    e.printStackTrace(stdout);
                }catch(IllegalArgumentException iae){
                    stdout.println("Message response IllegalArgumentException");
                    iae.printStackTrace(stdout);
                }
            }else
            {
                byte[] dummyRequest=helpers.buildHttpRequest(rInfo.getUrl()); // [TODO] POST plz
                int m_id=0;
                
                try{
                    while((m=Message.readDetails(dis,as))!=null){
                        for (int i=0;i<m.size();i++){
                            IParameter param;
                            switch(m.getPropertyTypeAt(i)){
                                case 1: // String
                                    param=helpers.buildParameter(String.format("string_%d_%d",m_id,i), helpers.urlEncode(m.getValueAt(i).toString()), IParameter.PARAM_BODY);
                                    dummyRequest=helpers.addParameter(dummyRequest, param);
                                    break;
                                case 3: // Integer
                                    param=helpers.buildParameter(String.format("int_%d_%d",m_id,i), m.getValueAt(i).toString(), IParameter.PARAM_BODY);
                                    dummyRequest=helpers.addParameter(dummyRequest, param);
                                    break;
                            }
                        }
                        m_id++;
                    }
                    dummyRequest=helpers.addParameter(dummyRequest, helpers.buildParameter("original", byteArrayToHex(body), IParameter.PARAM_BODY));
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
            HashMap<String,Integer> paramInts=new HashMap<String,Integer>(); 
            for (IParameter p: dummyRequest.getParameters()){
                if (p.getName().startsWith("string_")){
                    paramStrings.put(p.getName(), helpers.urlDecode(p.getValue()));
                }else if(p.getName().startsWith("int_")){
                    paramInts.put(p.getName(), Integer.parseInt(p.getValue()));
                }
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
                            String key=String.format("string_%d_%d",m_id,i);
                            if (paramStrings.containsKey(key)){
                                stdout.println("Setting String value for "+key);
                                m.setValueAt(i, paramStrings.get(key));
                            }else if (paramInts.containsKey(key)){
                                stdout.println("Setting Integer value for "+key);
                                m.setValueAt(i, paramInts.get(key));
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
            //messages.get(msgId).setValueAt(propId, new String(payload));

            ByteArrayOutputStream baos=new ByteArrayOutputStream();
            DataOutputStream dos=new DataOutputStream(baos);
            
            try{
                for (int i=0;i<messages.size();i++){
                    Message m=messages.get(i);
                    if (i == msgId){
                        m.setValueAt(propId, new String(payload));
                    }
                    m.writeDetails(new FormsDispatcher(), dos);
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
            stdout.println("Insertion Point Type queried");
            return INS_PARAM_BODY;
        }
        
    }
}
