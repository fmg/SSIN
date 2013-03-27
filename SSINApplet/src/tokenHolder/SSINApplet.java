/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package tokenHolder;

import javacard.framework.*;

/**
 *
 * @author Desktop
 */
public class SSINApplet extends Applet implements AppletEvent{

    //Applet CLA
    final static byte APPLET_CLA = (byte)0x80;
    
    
    /****************************************************
     * INS definitions                                  *
     ****************************************************/
    
    
    final static byte GET_SECRET_KEY = (byte)0x10;
    final static byte SET_SECRET_KEY = (byte)0x30;
    
    
     /****************************************************
     * ERROR codes definitions                         *
     ****************************************************/
    
    /* Common codes */
    final static short SW_MALFORMED_MSG = 0x6300;
    final static short SW_WRONG_PIN = 0x6301;
    final static short SW_EXCEPTION_ERROR = 0x6302;

    
    
    
    //OwnerPIN
    OwnerPIN cardPin;
    final static byte PIN_LIMIT = (byte)3;
    final static byte CARD_PIN_LENGTH = (byte)8;
    
    
    //Keys
    final static byte SECRET_KEY_LENGTH = (byte)24;
    byte[] secretKey; //3DES secret key
    
    
    
    private short[] transientBufferOffset;
    final static short BUFFER_INS = (short)0;
    final static short BUFFER_P1 = (short)1;
    final static short BUFFER_P2 = (short)2;
    final static short BUFFER_COUNT = (short)3; //offset to the latest sent byte count to CAT, only used in sending functions

    
    /**
     * buffer to be utilized when the apdu buffer is not enought
     */
    private byte[] transientBuffer = null;
    private short transientBufferCurrentLenght;
    final static short TRANSIENT_BUFFER_LENGTH = (short)2048; //2KB max buffer

    
    
    
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SSINApplet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected SSINApplet() {
        
        
        cardPin = new OwnerPIN(PIN_LIMIT, CARD_PIN_LENGTH);
        secretKey = new byte[SECRET_KEY_LENGTH];
        
        
        transientBuffer = JCSystem.makeTransientByteArray(TRANSIENT_BUFFER_LENGTH, JCSystem.CLEAR_ON_RESET);
        transientBufferCurrentLenght = (short)0;
        
        transientBufferOffset = JCSystem.makeTransientShortArray((short)4, JCSystem.CLEAR_ON_RESET);
        transientBufferOffset[0] = (short)0;
        transientBufferOffset[1] = (short)0;
        transientBufferOffset[2] = (short)0;
        transientBufferOffset[3] = (short)0;

        
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        //check if the apdu is for selecting the applet
        if(this.selectingApplet()){
            return;
        }
        
        //check CLA
        if((buffer[ISO7816.OFFSET_CLA] & (byte)0xF0) != (byte)APPLET_CLA){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        switch(buffer[ISO7816.OFFSET_INS]){
            
            
            case SET_SECRET_KEY:    card_set_secret_key(apdu, buffer);
                                    break;
                
            case GET_SECRET_KEY:    card_get_secret_key(apdu, buffer);
                                    break;
                            
                
                
            
            
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    public void uninstall() {
    }

    public boolean select() {
        return cardPin.getTriesRemaining() != (byte)0;
    }

    public void deselect() {
        super.deselect();
    }
    
    
    /***************************************************************************
     *                                                                         *
     *                                                                         *
     *                       SSIN APPLET functions                             *
     *                                                                         *
     *                                                                         *
     **************************************************************************/
    
    
    private void card_set_secret_key(APDU apdu, byte[] buffer) {
        
        apdu.setIncomingAndReceive();
        short Lc = apdu.getIncomingLength();
        
        
        if(Lc != (CARD_PIN_LENGTH + SECRET_KEY_LENGTH)){
            cardPin.check(buffer, (short)0, CARD_PIN_LENGTH); //make the pin miss, by passing apdu parameters
            ISOException.throwIt(SW_MALFORMED_MSG);
        }
        
        if(cardPin.check(buffer, apdu.getOffsetCdata(), CARD_PIN_LENGTH)){
            ISOException.throwIt(SW_WRONG_PIN);
        }

        try{
            JCSystem.beginTransaction();
            Util.arrayCopy(buffer, (short)(apdu.getOffsetCdata() + CARD_PIN_LENGTH), secretKey, (short)0, SECRET_KEY_LENGTH);
            JCSystem.commitTransaction();
        }catch(Exception ex){
            JCSystem.abortTransaction();
            ISOException.throwIt(SW_EXCEPTION_ERROR);
        }
        
        
        
    }

    
    
    private void card_get_secret_key(APDU apdu, byte[] buffer) {
        apdu.setIncomingAndReceive();
        short Lc = apdu.getIncomingLength();
        
        
        if(Lc != (short)0){
            ISOException.throwIt(SW_MALFORMED_MSG);
        }
        
        if(cardPin.check(buffer, apdu.getOffsetCdata(), CARD_PIN_LENGTH)){
            ISOException.throwIt(SW_WRONG_PIN);
        }

        Util.arrayCopy(secretKey, (short)0, buffer, (short)0, SECRET_KEY_LENGTH);
        apdu.setOutgoingAndSend((short)0, SECRET_KEY_LENGTH);
        
    }

 
    
    /***************************************************************************
     *                                                                         *
     *                                                                         *
     *                              UTILS                                      *
     *                                                                         *
     *                                                                         *
     **************************************************************************/
    
    
    /**
     * Resets the state of the auxiliary buffer offset
     */
    private void resetExtendedBufferState(){
        
        transientBufferCurrentLenght = (short)0;
        transientBufferOffset[BUFFER_INS] = (short)0;
        transientBufferOffset[BUFFER_P1] = (short)0;
        transientBufferOffset[BUFFER_P2] = (short)0;
        transientBufferOffset[BUFFER_COUNT] = (short)0;
        
    }
    
    
    
    private void  receiveExtendedData(APDU apdu, byte [] buffer, short bufferStartOffset, short apduRecvLen) {

        short bufOffset = 0;

        Util.arrayCopy(buffer, bufferStartOffset, transientBuffer, (short)(transientBufferCurrentLenght + bufOffset), apduRecvLen);
        do{
            bufOffset += apduRecvLen;
            apduRecvLen= apdu.receiveBytes((short)0);
            Util.arrayCopy(buffer, (short)0, transientBuffer, (short)(transientBufferCurrentLenght +bufOffset), apduRecvLen);
        }while(apduRecvLen >0);
        
        transientBufferCurrentLenght += bufOffset;
    }
    
    
    
    private void sendExtendedDataChaining(APDU apdu, byte[] buffer, byte[] source ,short actualLe) {

        apdu.setOutgoing();

        apdu.setOutgoingLength((short)(actualLe +1));//we need to add the byte indicating if there are more APDUS, thus the APDU_MAX_LENGTH = 254
        
        //check if there are more apdus to be sent (chain apdu)
        if((short)(transientBufferOffset[BUFFER_COUNT] + actualLe) == transientBufferCurrentLenght){
           
            buffer[(short)0] = (byte)0;//no more apdus
            apdu.sendBytes((short)0, (short)1);
            apdu.sendBytesLong(source, transientBufferOffset[BUFFER_COUNT], actualLe);
            
            transientBufferOffset[BUFFER_INS] = (short)0;
            transientBufferOffset[BUFFER_P1] = (short)0;
            transientBufferOffset[BUFFER_P2] = (short)0;
            transientBufferOffset[BUFFER_COUNT] = (short)0;
            transientBufferCurrentLenght = (short)0;
            
        }else{

            buffer[(short)0] = (byte)1; //more bytes
            apdu.sendBytes((short)0, (short)1);
            apdu.sendBytesLong(source, transientBufferOffset[BUFFER_COUNT], actualLe);

            transientBufferOffset[BUFFER_COUNT] += actualLe;
            transientBufferOffset[BUFFER_P1]++;
        }
 
    }
    
    
    
    private byte receiveExtendedDataChaining(APDU apdu, byte[] buffer ,boolean verifyManagementPin, byte functionINS){
        
        short recvLen =apdu.setIncomingAndReceive();
        short Lc = apdu.getIncomingLength();
        
        
        //when p1 > p2 in the same function there is chain receiving and sending
        if(transientBufferOffset[BUFFER_INS] == functionINS && 
                buffer[ISO7816.OFFSET_P1] > buffer[ISO7816.OFFSET_P2]){
            
            //when p1 > p2 there must have been sent information, so TRANSIENT_BUFFER_COUNT cant be 0
            if(transientBufferOffset[BUFFER_COUNT] == 0){ //must have sent something in the final receiving apdu (when p1 == p2)    
                resetExtendedBufferState();
                ISOException.throwIt(SW_MALFORMED_MSG);
            }else{
                return 0x02;
            }
        }
        
        if(transientBufferOffset[BUFFER_INS] == (byte)0 && 
                transientBufferOffset[BUFFER_P1] == (short)0){//first call of receive, extended buffer auxiliary structure is empty
            
            
            if(buffer[ISO7816.OFFSET_P1] != 0x01){//must be first
                ISOException.throwIt(SW_MALFORMED_MSG);
            }
            
            transientBufferCurrentLenght = (short)0;
            transientBufferOffset[BUFFER_INS] = functionINS;
            transientBufferOffset[BUFFER_P2] = buffer[ISO7816.OFFSET_P2];
            transientBufferOffset[BUFFER_P1] = 0x01;
            transientBufferOffset[BUFFER_COUNT] = (short)0;
            
          
            receiveExtendedData(apdu, buffer, apdu.getOffsetCdata(), recvLen);

            
            if(transientBufferOffset[BUFFER_P1] == transientBufferOffset[BUFFER_P2]){//last apdu to bring information
                 return 0x00;
            }else{
                transientBufferOffset[BUFFER_P1]++;
                return 0x01;
            }
            
        }else{//rest of the chaining apdus
            if(transientBufferOffset[BUFFER_INS] != functionINS && 
                    transientBufferOffset[BUFFER_P1] != buffer[ISO7816.OFFSET_P1] &&
                    transientBufferOffset[BUFFER_P2] != buffer[ISO7816.OFFSET_P2]){
                
                resetExtendedBufferState();
                ISOException.throwIt(SW_MALFORMED_MSG);
            }
            
            
            receiveExtendedData(apdu, buffer, apdu.getOffsetCdata(), recvLen);
            
            
            if(transientBufferOffset[BUFFER_P1] == transientBufferOffset[BUFFER_P2]){//last apdu to bring information

                return 0x00;
            }else{
                transientBufferOffset[BUFFER_P1]++;
                return 0x01;
            }   
        }
        
  
    }

    
    
}
