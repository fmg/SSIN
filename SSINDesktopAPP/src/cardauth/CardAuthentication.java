/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cardauth;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import encriptionLogic.CardMediator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;
import serverSimulation.ServerSimulator;

/**
 *
 * @author Desktop
 */
public class CardAuthentication {
    
    private KeyStore userKeyStore;
    private Certificate userCertificate;
    private CardMediator cardAPI;

    
    private static CardAuthentication cardAuth;
    
    
    private CardAuthentication() throws Exception {
        cardAPI = CardMediator.getObjectInstance();
    }
    
    /**
    * Cloning is not supported due to the object being singleton
    */
    @Override
   public Object clone() throws CloneNotSupportedException {
           throw new CloneNotSupportedException();
   }
    
    
    public synchronized static CardAuthentication getObjectInstance() throws Exception {
        if (cardAuth == null) {
                cardAuth = new CardAuthentication();
        }
        return cardAuth;
    }
    
    
    public void getKeyStoreForSSL(String password) throws Exception{
        
            userKeyStore = cardAPI.getKeyStore(password);
            
            Enumeration<String> e = userKeyStore.aliases();
            String aliasName = null;
            while (e.hasMoreElements()) {
                aliasName = e.nextElement();
                if (userKeyStore.isKeyEntry(aliasName)) {
                    userCertificate = (userKeyStore.getCertificate(aliasName));
                }
            }

            if (userCertificate == null) {
                throw new Exception("Certificate not found in keystore");

            }
          
    }
    
    
    
    public boolean authenticateWithServer() throws Exception{
        
            ServerSimulator servSim = ServerSimulator.getObjectInstance();
            
            String responseJSON = servSim.getAuthToken(userCertificate);
            
            
            JsonObject  jObj = new JsonParser().parse(responseJSON).getAsJsonObject();
            int status = jObj.get("status").getAsInt();
            String token = jObj.get("token").getAsString();
        
        
            byte[] responseToken = cardAPI.getAuthTokenResponse(token);
            if(!servSim.verifyToken(responseToken)){
                return false;
            }
            
            return true;
    }
    
}
