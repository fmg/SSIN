/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package serverSimulation;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Desktop
 */
public class ServerSimulator {

    //server status
    private final static int STATUS_OK = 0;
    private final static int STATUS_INVALID_CERT = 1;
    private final static int STATUS_SERVER_ERROR = 2;
    
    
    //server variables   
    private final static String SERVER_KEYSTORE_FILE = "server.p12";
    private final static String SERVER_KEYSTORE_PASSWORD = "ssin2013";
    private final static String CARD_PROTOCOL_ALGORITHM = "HmacSHA1";
    private final static long PROTOCOL_MAX_TIMEOUT = 3;//3 mins to answer => 3*60*1000 => 180 000 ms
    private final static int SECURE_RANDOM_LENGTH = 8;//long, DO NOT CHANGE!
    private SecureRandom randGen;
    private Certificate serverCert;
    private KeyStore serverKS;
    private Signature signing;
    
    
    //card autentication
    private final static String CLIENT_PROTOCOL_SECRET_KEY_FILE = "client.cer";
    private String cardResponseCorrectAnswer;
    private long answerTimeout;
    private RSAPublicKey clientPredefinedPK;
    
    
    
    private static ServerSimulator serverSim;

    private ServerSimulator() throws Exception {

        Security.addProvider(new BouncyCastleProvider());


        randGen = new SecureRandom();
        signing = Signature.getInstance("SHA1withRSA");


        byte[] bytes = extractDataFromFile(new File(SERVER_KEYSTORE_FILE));
        serverKS = KeyStore.getInstance("PKCS12", "BC");
        serverKS.load(new ByteArrayInputStream(bytes), SERVER_KEYSTORE_PASSWORD.toCharArray());


        Enumeration<String> e = serverKS.aliases();
        String aliasName = null;
        while (e.hasMoreElements()) {
            aliasName = e.nextElement();
            if (serverKS.isKeyEntry(aliasName)) {
                serverCert = (serverKS.getCertificate(aliasName));
            }
        }

        if (serverCert == null) {
            throw new Exception("Server Certificate not found in PKCS12 File");

        }

    }

    public static ServerSimulator getObjectInstance() throws Exception {
        if (serverSim == null) {
            serverSim = new ServerSimulator();
        }
        return serverSim;
    }

    public String getAuthToken(Certificate clientCert) {

        Gson gson = new Gson();
        String responseJSON = "";

        Map<String, Object> responseMap = new HashMap<String, Object>();

        try {

            clientCert.verify(serverCert.getPublicKey());
        } catch (Exception ex) {
            responseMap.put("status", STATUS_INVALID_CERT);
            responseMap.put("token", "");
            responseJSON = gson.toJson(responseMap);
            return responseJSON;
        }


        String clientToken = "";
        String timeStamp = String.valueOf(System.currentTimeMillis());
        System.out.println(timeStamp);
        String nounce = String.valueOf(ByteBuffer.wrap(
                randGen.generateSeed(SECURE_RANDOM_LENGTH)).getLong());
        System.out.println(nounce);

        clientToken = timeStamp + nounce;

        responseMap.put("status", STATUS_OK);
        responseMap.put("token", clientToken);
        responseJSON = gson.toJson(responseMap);
         
         return responseJSON;



    }

    public boolean verifyToken(String token) {

        try {
            CertificateFactory crt_fctry = new CertificateFactory();
            FileInputStream fis;


            fis = new FileInputStream(CLIENT_PROTOCOL_SECRET_KEY_FILE);
            X509Certificate cardCert = (X509Certificate) crt_fctry.engineGenerateCertificate(fis);

            clientPredefinedPK = (RSAPublicKey) cardCert.getPublicKey();
        
            
            signing.initVerify(clientPredefinedPK);
            signing.update(cardResponseCorrectAnswer.getBytes());
            signing.verify(token.getBytes());
            
            return true;

        } catch (Exception ex) {
            return false;
        }


    }

    private byte[] extractDataFromFile(File filePath) throws FileNotFoundException, IOException {


        FileInputStream fis = new FileInputStream(filePath);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        byte readBuf[] = new byte[1024];
        int readCnt = fis.read(readBuf);
        while (0 < readCnt) {
            bout.write(readBuf, 0, readCnt);
            readCnt = fis.read(readBuf);
        }

        fis.close();

        return bout.toByteArray();

    }

    private String byteArrayToHexString(byte[] bArray) {

        String response = "";
        for (byte b : bArray) {
            if ((short) (b & 0xff) < (short) 16) {
                response += "0x0" + (Integer.toString((b & 0xff), 16)).toUpperCase() + " ";
            } else {
                response += "0x" + (Integer.toString((b & 0xff), 16)).toUpperCase() + " ";
            }

        }

        return response;
    }
}
