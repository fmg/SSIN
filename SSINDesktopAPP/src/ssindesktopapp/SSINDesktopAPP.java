/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ssindesktopapp;

import encriptionLogic.CardMediator;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import javax.smartcardio.CardException;

/**
 *
 * @author Desktop
 */
public class SSINDesktopAPP {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws CardException, Exception {
        // TODO code application logic here
        
        
        CardMediator cm = CardMediator.getObjectInstance();
        
        Object[] readers = cm.getCardReaders();
        cm.setCardReader(0);
        cm.openChannel();
        cm.selectApplet();
        
        
        List<SecretKey> klist = cm.getSecretKeys();
        
        cm.closeChannel();
    }
}
