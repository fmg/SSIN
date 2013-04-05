/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encriptionLogic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Desktop
 */
public class CardMediator {
    
    
    //Applet AID
    private final static byte[] appletAID = {   (byte)0xFC, (byte)0x5A, (byte)0xB1, 
                                                (byte)0x77, (byte)0x42, (byte)0x22};
    
    
    //Applet CLA
    private final static byte APPLET_CLA = (byte)0x80;
    
    private final static int APDU_MAX_DATA_LENGHT = 255;
    private final static int APDU_RESERVED_BYTES = 5;
    private final static int APDU_RESPONSE_SUCCESS = 36864; //(short)0x9000;
    
    
    /****************************************************
     * INS definitions                                  *
     ****************************************************/

    final static byte INS_GET_SECRET_KEYS = (byte)0x10;
    final static byte INS_GET_KEY_STORE = (byte)0x11;
    final static byte INS_GET_AUTH_TOKEN_RESPONSE = (byte)0x12;
    
    
    
    
   
    
    
    
    private static CardMediator cardAPI;

    private TerminalFactory factory;
    private List<CardTerminal> terminals;
    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;
    private final static String protocol = "t=0";
    private ResponseAPDU responseApdu;

    private static String KEYS_ALGORITHM = "DESede";
    private static int SECRET_KEY_LENGTH = 24;

    
    private CardMediator() throws CardException{
        card = null;
        
        factory = TerminalFactory.getDefault();
        terminals = factory.terminals().list();
        
        Security.addProvider(new BouncyCastleProvider());  

        
    }
    
    
    /**
    * Cloning is not supported due to the object being singleton
    */
    @Override
   public Object clone() throws CloneNotSupportedException {
           throw new CloneNotSupportedException();
   }
    
    public synchronized static CardMediator getObjectInstance() throws CardException {
        if (cardAPI == null) {
                cardAPI = new CardMediator();
        }
        return cardAPI;
    }
    
    
    public Object[] getCardReaders(){
        return terminals.toArray();
    }
    
    
    public boolean setCardReader(int option) throws Exception{
        
        if(option > (terminals.size()-1)) {
            return false;
        }
        
        terminal = terminals.get(option);
        
        openChannel();
        selectApplet();
        
        return true;
        
    }

    
    public void openChannel() throws CardException{
        
        if(card == null || channel == null){
            card = terminal.connect(protocol);
            channel = card.getBasicChannel();
        }
    }
    
    
    public void closeChannel() throws CardException{
        card.disconnect(true);
    }
    
    
    
    public void selectApplet() throws CardException, Exception{
        if(!terminal.isCardPresent()){
            throw new CardException("ERROR: Card is not present");
        }
       
        
        byte[] apdu = new byte[APDU_RESERVED_BYTES+appletAID.length];
        apdu[0] = (byte)0x00;//cla
        apdu[1] = (byte)0xA4;//ins
        apdu[2] = (byte)0x04;//p1
        apdu[3] = (byte)0x00;//p2
        apdu[4] = (byte)(appletAID.length);
        
        System.arraycopy(appletAID, 0, apdu, 5, appletAID.length);
       
        //send apdu
        responseApdu = channel.transmit(new CommandAPDU(apdu));
        int apduStatus = responseApdu.getSW();
        
        if(apduStatus != APDU_RESPONSE_SUCCESS){
            throw new Exception("Could not select applet");
        }
    }
    
    
    public List<SecretKey> getSecretKeys() throws CardException, Exception{
        byte[] apdu = new byte[APDU_RESERVED_BYTES];
        apdu[0] = APPLET_CLA;//cla
        apdu[1] = INS_GET_SECRET_KEYS;//ins
        apdu[2] = (byte)0x00;//p1
        apdu[3] = (byte)0x00;//p2
        apdu[4] = (byte)0x00;//LC
       
        //send apdu
        responseApdu = channel.transmit(new CommandAPDU(apdu));
        
        int apduStatus = responseApdu.getSW();
        
        if(apduStatus != APDU_RESPONSE_SUCCESS){
            throw new Exception("Could not get keys");
        }
        
        byte[] keys = responseApdu.getData();
        
        
        
        
        List<SecretKey> keyList = new ArrayList<SecretKey>(2);
        
        byte[] encKeyBuffer = new byte[SECRET_KEY_LENGTH];
        byte[] signKeyBuffer = new byte[SECRET_KEY_LENGTH];
        System.arraycopy(keys, 0, encKeyBuffer, 0, SECRET_KEY_LENGTH);
        System.arraycopy(keys, SECRET_KEY_LENGTH, signKeyBuffer, 0, SECRET_KEY_LENGTH);

        
        SecretKey enckeySpec = new SecretKeySpec(encKeyBuffer, KEYS_ALGORITHM);
        SecretKey signkeySpec = new SecretKeySpec(signKeyBuffer, KEYS_ALGORITHM);
        
        keyList.add(enckeySpec);
        keyList.add(signkeySpec);
        
        
        return keyList;
        
    }
    
    
    public KeyStore getKeyStore(String password) throws Exception{
        
        byte P1 = (byte)0x00;
        
        byte[] apdu = new byte[APDU_RESERVED_BYTES];
        apdu[0] = APPLET_CLA;//cla
        apdu[1] = INS_GET_KEY_STORE;//ins
        apdu[2] = P1;
        apdu[3] = (byte)0x00;//p2
        apdu[4] = (byte)0x00;//LC
        
        //send apdu
        responseApdu = channel.transmit(new CommandAPDU(apdu));
        
        int status = responseApdu.getSW();   
        
        if(status != APDU_RESPONSE_SUCCESS){
            throw new Exception("Could not get keystore");
        }
        
        
        byte[] resp = responseApdu.getData();
        ByteArrayOutputStream keystoreBuff = new ByteArrayOutputStream();
        
        boolean moreAPDUS;
        do{
            moreAPDUS = moreBytes(resp[0]);
            keystoreBuff.write(resp,1, resp.length-1);
            
            if(moreAPDUS){
                P1++;
                apdu[2] = P1;
                responseApdu = channel.transmit(new CommandAPDU(apdu));
                resp = responseApdu.getData();
                
            }
            status = responseApdu.getSW();
        
        }while(moreAPDUS && status == APDU_RESPONSE_SUCCESS);		

        
        if(status != APDU_RESPONSE_SUCCESS){
            throw new Exception("Could not get keystore");
        }

        
        KeyStore store = KeyStore.getInstance("PKCS12", "BC"); 
        store.load(new ByteArrayInputStream(keystoreBuff.toByteArray()), password.toCharArray()); 
        
        
        return store;
    }
    
    
    
    
    public byte[] getAuthTokenResponse(String authToken) throws Exception{
 
        byte[] tokenBytes = authToken.getBytes();      
        
        if(tokenBytes.length > APDU_MAX_DATA_LENGHT){
            return new byte[0];
        }
        
        byte[] apdu = new byte[APDU_RESERVED_BYTES + tokenBytes.length];
        apdu[0] = APPLET_CLA;//cla
        apdu[1] = INS_GET_AUTH_TOKEN_RESPONSE;//ins
        apdu[2] = (byte)0x01;//p1
        apdu[3] = (byte)0x01;//p2
        apdu[4] = (byte)tokenBytes.length;//LC
        
        System.arraycopy(tokenBytes, 0, apdu, 5, tokenBytes.length);

       
        //send apdu
        responseApdu = channel.transmit(new CommandAPDU(apdu));
        
        int apduStatus = responseApdu.getSW();
        
        if(apduStatus != APDU_RESPONSE_SUCCESS){
            throw new Exception("Could not get keys");
        }
        
        byte[] resp = responseApdu.getData();

        return resp;
        
    }
    
    
    /***************************************************************************
     *                                                                         *
     *                                                                         *
     *                              UTILS                                      * 
     *                                                                         *
     *                                                                         *
     **************************************************************************/
    
    
    
    private boolean moreBytes(byte b){
            return b == (byte)0x01;
    }
    
    
     /**
     * Converts the byte array into a hex string
     * 
     * @param bArray - byte array
     * 
     * @return hex string representation of the byte array 
     */
    private String byteArrayToHexString(byte[] bArray){
       
        String response = "";
       for(byte b:bArray){
           if((short)(b & 0xff) < (short)16)
                response+= "0x0" + (Integer.toString((b & 0xff), 16)).toUpperCase() + " ";
            else
                response+= "0x" + (Integer.toString((b & 0xff), 16)).toUpperCase() + " ";
 
       }

       return response;
    }
    
    
    
    private byte[] strToHexByte(String string) {
        
        byte[] b = new byte[string.length() / 2];
        try {
            String s1;

            int j=0;
            for(int i = 0; i < string.length(); i += 2) {
                s1 = string.substring(i, i + 2);
                b[j] = (byte)Integer.parseInt(s1, 16);
                j++;
            }
        } catch(NumberFormatException ex) {
            ex.printStackTrace();
        } catch(StringIndexOutOfBoundsException ex) {
            ex.printStackTrace();
        }

        return b;
    }
    
    
    
    private void reverse(byte[] array) {
      if (array == null) {
          return;
      }
      int i = 0;
      int j = array.length - 1;
      byte tmp;
      while (j > i) {
          tmp = array[j];
          array[j] = array[i];
          array[i] = tmp;
          j--;
          i++;
      }
  }
    
}
