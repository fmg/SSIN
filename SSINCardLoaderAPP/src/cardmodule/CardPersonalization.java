/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cardmodule;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.JTextArea;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Desktop
 */
public class CardPersonalization {
    
    //Applet AID
    private final static byte[] appletAID = {   (byte)0xFC, (byte)0x5A, (byte)0xB1, 
                                                (byte)0x77, (byte)0x42, (byte)0x22};
    
    
    //Applet CLA
    private final static byte APPLET_CLA = (byte)0x80;
    
    
    
    private final static int PIN_LENGTH = 8;
    private final static int SECRET_KEY_LENGTH = 24;
    private final static int APDU_MAX_DATA_LENGHT = 255;
    private final static int APDU_RESERVED_BYTES = 5;
    private final static int APDU_RESPONSE_SUCCESS = 36864; //(short)0x9000;
    
    
    
    //INS
    final static byte INS_SET_SECRET_KEYS = (byte)0x30;
    final static byte INS_SET_CARD_PIN = (byte)0x31;
    final static byte INS_SET_RSA_PRIVATE_KEY = (byte)0x32;
    final static byte INS_SET_KEY_STORE = (byte)0x33;
    
    
    
    private TerminalFactory factory;
    private List<CardTerminal> terminals;
    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;
    private final static String protocol = "t=0";
    private ResponseAPDU responseApdu;
    
    
    
    public CardPersonalization() throws CardException{
        card = null;
        
        factory = TerminalFactory.getDefault();
        terminals = factory.terminals().list();
        
        Security.addProvider(new BouncyCastleProvider());  
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
    
    
    private void selectApplet() throws CardException, Exception{
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
    
    
    
    public boolean sendToCard(String pin, String encDecSecretKeyPath, String sigSecretKeyPath, String rsaPrivKeyPath, String keyStorePath, JTextArea outputConsole){
        
        
        try{
        
            Integer.parseInt(pin);//if parsing throw expection (not number), the pin is invalid
            
            if(pin.length() != PIN_LENGTH){
                outputConsole.append("\nInvalid Pin length: ");
                return false;
            }
        }catch(Exception ex){
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("\nInvalid Pin: " + ex.getMessage() + "\n");
            return false;
        }
        
        byte[] pinArray = getBytesFromPin(Integer.parseInt(pin));
        byte[] encDecSecretKey = null;
        byte[] sigSecretKey = null;
        byte[] rsaKey = null;
        byte[] keystore = null;
        RSAPrivateKey privateKey = null;
        
        try {
            encDecSecretKey = extractDataFromFile(encDecSecretKeyPath);
            sigSecretKey = extractDataFromFile(sigSecretKeyPath);
            rsaKey = extractDataFromFile(rsaPrivKeyPath);
            keystore = extractDataFromFile(keyStorePath);
        
            
            if(encDecSecretKey.length != SECRET_KEY_LENGTH || sigSecretKey.length != SECRET_KEY_LENGTH){
                outputConsole.append("\nInvalid Secret Key size, must be 24 byte long");
                return false;
            }
            
        } catch(Exception ex){
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("\nCould not retrieve keys from files: " + ex.getMessage() + "\n");
            return false;
        }
        
        try{
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(rsaKey);
            KeyFactory generator = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateKey) generator.generatePrivate(privateKeySpec);
            
        }catch(Exception ex){
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("\nInvalid RSA private key: " + ex.getMessage() + "\n");
            return false;
        }
        
        
        
         outputConsole.append("\nInitializing Card\n");
        try {
            card = terminal.connect(protocol);
            channel = card.getBasicChannel();
        } catch (CardException ex) {
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("\nCould not connect to the card: " + ex.getMessage() + "\n");
            return false;
        }     
        
        
        byte[] atr = card.getATR().getBytes();
        outputConsole.append("Getting ATR\n"+ byteArrayToHexString(atr) +"\n\n");
        
        try {
            outputConsole.append("Selecting applet "+ appletAID +"\n");
            selectApplet();
        } catch (Exception ex) {        
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("Selection failed : " + ex.getMessage()+ "\n");
            return false;
        }
        
        
        try {
            outputConsole.append("Sending PINS\n");
            sendPin(pinArray);
        } catch (Exception ex) {
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("Could not send pin : " + ex.getMessage() + "\n");
            return false;
        }
        
         try {
            outputConsole.append("Sending Secret Keys\n");
            sendSecretKeys(encDecSecretKey,sigSecretKey,pinArray);
        } catch (Exception ex) {
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("Could not send keys : " + ex.getMessage() + "\n");
            return false;
        }
         
         
        try {
            outputConsole.append("Sending Key Store\n");
            sendKeyStore(keystore, pinArray);
        } catch (Exception ex) {
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("Could not send Key Store : " + ex.getMessage() + "\n");
            return false;
        }
        
        
        try {
            outputConsole.append("Sending RSA Private Key\n");
            sendPrivateKey(privateKey, pinArray);
        } catch (Exception ex) {
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
            outputConsole.append("Could not send Key Store : " + ex.getMessage() + "\n");
            return false;
        }
        
        
        try {
            card.disconnect(true);
        } catch (CardException ex) {
            outputConsole.append("\nCould not close the connection to the card\n");
            Logger.getLogger(CardPersonalization.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        outputConsole.append("Operations completed\n");
        
        return true;
    }
    
    
    private void sendPin(byte[] cardPin) throws CardException{
        
        byte[] data = new byte[PIN_LENGTH];
        System.arraycopy(cardPin, 0, data, 0, PIN_LENGTH);
        
        sendAPDUWithNoResponseData(data, INS_SET_CARD_PIN);
    }
    
    
    
    private void sendPrivateKey(RSAPrivateKey privKey, byte[] pin) throws CardException{
        
        byte[] pmod = privKey.getModulus().toByteArray();
        byte[] pexp = privKey.getPrivateExponent().toByteArray();
        
        int keySize = privKey.getModulus().bitLength() / 8;
        
        if(pmod.length > keySize){//since its translated to a bin integer the sign bit might make it 257 bits long
            byte[] pmod2 = new byte[keySize];
            System.arraycopy(pmod, 1, pmod2, 0, keySize);
            pmod = pmod2;
        }
        
        if(pexp.length > keySize){//since its translated to a bin integer the sign bit might make it 257 bits long
            byte[] pexp2 = new byte[keySize];
            System.arraycopy(pexp, 1, pexp2, 0, keySize);
            pexp = pexp2;
        }
        
        
        System.out.println("\nPrivate Key Modulus : \n" + byteArrayToHexString(pmod));
        System.out.println("\n\nPrivate Key exponent : \n" + byteArrayToHexString(pexp) + "\n\n");
        
        
        byte[] data = new byte[2*keySize + PIN_LENGTH];
        System.arraycopy(pin, 0, data, 0, PIN_LENGTH);
        System.arraycopy(pmod, 0, data, PIN_LENGTH, keySize);
        System.arraycopy(pexp, 0, data, keySize + PIN_LENGTH, keySize);
        
        sendAPDUWithNoResponseData(data, INS_SET_RSA_PRIVATE_KEY);
    }
    
    
    
    private void sendSecretKeys(byte[] encryption_decryptionSecretKey, byte[] signatureSecretKey, byte[] pin) throws CardException{
                
        
        byte[] data = new byte[2*SECRET_KEY_LENGTH + PIN_LENGTH];
        System.arraycopy(pin, 0, data, 0, PIN_LENGTH);
        System.arraycopy(encryption_decryptionSecretKey, 0, data, PIN_LENGTH, SECRET_KEY_LENGTH);
        System.arraycopy(signatureSecretKey, 0, data, SECRET_KEY_LENGTH+ PIN_LENGTH, SECRET_KEY_LENGTH);
        
        sendAPDUWithNoResponseData(data, INS_SET_SECRET_KEYS);
    }
    
    
    
    private void sendKeyStore(byte[] keystore, byte[] pin) throws CardException{
        
        
        byte[] data = new byte[keystore.length + PIN_LENGTH];
        System.arraycopy(pin, 0, data, 0, PIN_LENGTH);
        System.arraycopy(keystore, 0, data, PIN_LENGTH, keystore.length);
        
        sendAPDUWithNoResponseData(data, INS_SET_KEY_STORE);
        
    }
    
    
    
    /***************************************************************************
     *                                                                         *
     *                                                                         *
     *                              UTILS                                      *
     *                                                                         *
     *                                                                         *
     **************************************************************************/
    
    
    public byte[] getBytesFromPin(int pin){
        int offset = 0;
        byte[] secPin = new byte[PIN_LENGTH];
        while(pin%10 > 0){
            secPin[offset] = (byte)((pin%10));
            pin/=10;
            offset++;
        }

         
        reverse(secPin);
        return secPin;
    }
    
    
    private void sendAPDUWithNoResponseData(byte[] data, byte INS) throws CardException{

        int numberOfApdus = data.length/APDU_MAX_DATA_LENGHT;
        if(data.length%APDU_MAX_DATA_LENGHT > 0){
            numberOfApdus++;
        }
        
        
        int dataSent = 0;
        int apduStatus;
        
        for(int i = 0; i < numberOfApdus; i++){
            
            int dataToBeSent;
            
            byte[] apdu = null;
            if(data.length - dataSent > APDU_MAX_DATA_LENGHT){
                dataToBeSent = APDU_MAX_DATA_LENGHT;
                apdu = new byte[dataToBeSent+APDU_RESERVED_BYTES];
                apdu[4] = (byte)0xFF;

            }else{
                dataToBeSent = data.length - dataSent;
                apdu = new byte[APDU_RESERVED_BYTES + dataToBeSent];
                apdu[4] = (byte) ((short)(dataToBeSent) & 0xff);

            }
            
            apdu[0] = APPLET_CLA;
            apdu[1] = INS;
            apdu[2] = (byte)(i+1);
            apdu[3] = (byte)(numberOfApdus);
            System.arraycopy(data, dataSent, apdu, 5, dataToBeSent);
            dataSent+= dataToBeSent;
            
            System.out.println(byteArrayToHexString(apdu));
            
        
          
            responseApdu = channel.transmit(new CommandAPDU(apdu));
            
            
             apduStatus = responseApdu.getSW();
            
            if(apduStatus != APDU_RESPONSE_SUCCESS){
                throw new CardException("Card rejected APDU with status code: "+apduStatus + "\n");
            }
            
        }
        
    }
    
    
    private byte[] extractDataFromFile(String filePath) throws FileNotFoundException, IOException{
        
        
        FileInputStream fis = new FileInputStream(filePath);
        ByteArrayOutputStream bout= new ByteArrayOutputStream();
            
        byte readBuf[] = new byte[1024];
        int readCnt = fis.read(readBuf);
        while (0 < readCnt) {
                bout.write(readBuf, 0, readCnt);
                readCnt = fis.read(readBuf);
        }

        fis.close();

        return  bout.toByteArray();
            
    }
    
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



