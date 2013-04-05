/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cardauth;

import java.security.KeyStore;

/**
 *
 * @author Desktop
 */
public class CardAuthentication {
    
    KeyStore userKeyStore;

    
    private static CardAuthentication cardAuth;
    
    
    private CardAuthentication() {
    }
    
    
    public synchronized static CardAuthentication getObjectInstance() {
        if (cardAuth == null) {
                cardAuth = new CardAuthentication();
        }
        return cardAuth;
    }
    
    
    
}
