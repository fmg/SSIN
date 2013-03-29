/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encriptionLogic;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Desktop
 */
public class EncriptionModule {
    
    private static String TRIPLE_DES_TRANSFORMATION = "DESede/ECB/PKCS5Padding";
    private static String ALGORITHM = "DESede";
    private static String BOUNCY_CASTLE_PROVIDER = "BC";
    private static String HMAC_ALGORITHM = "HmacSHA256";

    private Cipher encrypter;
    private Cipher decrypter;
    private Mac signing;

    
    private static EncriptionModule encAPI;
    
    private EncriptionModule() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException {
        
        Security.addProvider(new BouncyCastleProvider());
        encrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        decrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        signing = Mac.getInstance(HMAC_ALGORITHM);
        
    }
    
    
    public static EncriptionModule getObjectInstance() throws Exception  {
        if (encAPI == null) {
                encAPI = new EncriptionModule();
        }
        return encAPI;
    }
    
    
    public void loadInformationFromCard() throws Exception{
        
        CardMediator cm = CardMediator.getObjectInstance();
                
        cm.openChannel();
        cm.selectApplet();
        
        
        List<SecretKey> keys = cm.getSecretKeys();
        
        encrypter.init(Cipher.ENCRYPT_MODE, keys.get(0));
        decrypter.init(Cipher.DECRYPT_MODE, keys.get(0));

        signing.init(keys.get(1));
        
        cm.closeChannel();

        
    }
    
    
    
    
       
       
       
    
}
