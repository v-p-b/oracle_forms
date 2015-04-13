import java.io.*;
import oracle.forms.engine.FormsMessage;
import oracle.forms.engine.Message;

class MessageTester{

    // Borrowed from https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    private static void printMessage(Message m){
        for (int i=0;i<m.size();i++){
            System.out.println("Property "+i+": "+m.getPropertyAt(i)+" Type: "+m.getPropertyTypeAt(i));
            System.out.println("--- Value: "+m.getValueAt(i).toString());
            System.out.flush();
        }
    }

    public static void main(String argv[]){
    	String bodyHex=argv[0];
    	String[] as=new String[256];
        System.out.println(bodyHex);
        byte[] body=hexStringToByteArray(bodyHex);
        System.out.println("Body: "+body.length+" byte(s)");
        if (body.length==0) return;
        try{
            Message m;
            ByteArrayInputStream bis=new ByteArrayInputStream(body);
            DataInputStream dis=new DataInputStream(bis);
            while((m=Message.readDetails(dis,as))!=null){
                printMessage(m);
                System.out.println("Message OK");
                
                dis.mark(16);
            	System.out.print("Read finished at:");
            	for (int i=0;i<8;i++){
            		System.out.print(String.format("%02x", dis.readByte()));
            	}
            	dis.reset();
            	System.out.println("");
            	System.out.flush();
            	
            }
        }catch(IOException e){
            System.out.println("Message IOException");
            e.printStackTrace(System.out);
        }catch(IllegalArgumentException iae){
            System.out.println("Message IllegalArgumentException");
            iae.printStackTrace(System.out);
        }
        System.out.println("---");

    }
}
