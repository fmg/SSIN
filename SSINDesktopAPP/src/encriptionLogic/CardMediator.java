/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encriptionLogic;

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

    final static byte GET_SECRET_KEYS = (byte)0x10;
    
    
    
    
   
    
    
    
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
    
    
    public boolean setCardReader(int option){
        
        if(option > (terminals.size()-1)) {
            return false;
        }
        
        terminal = terminals.get(option);
        return true;
        
    }

    
    public void openChannel() throws CardException{
        card = terminal.connect(protocol);
        channel = card.getBasicChannel();
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
        apdu[1] = GET_SECRET_KEYS;//ins
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
    
    
    /***************************************************************************
     *                                                                         *
     *                                                                         *
     *                              UTILS                                      * 
     *                                                                         *
     *                                                                         *
     **************************************************************************/
    
    
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
