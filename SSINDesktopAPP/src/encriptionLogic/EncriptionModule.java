/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encriptionLogic;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

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
    
    
    private byte[] encript(byte[] fileContent){
        try {
            return encrypter.doFinal(fileContent);
        } catch(Exception ex){
            return new byte[0];
        }
        
    }
    
    private byte[] decript(byte[] encriptedFileContent){
        try {
            return decrypter.doFinal(encriptedFileContent);
        } catch (Exception ex) {
            return new byte[0];
        } 
    }
    
    
    public boolean encryptFile(String filePath, String encryptionPathFolder, String metadataKeywords){
        try {
            File originalFile = new File(filePath);
            String encryptionFilePath = encryptionPathFolder +  System.getProperty("file.separator") + originalFile.getName();
            
            System.out.println(encryptionFilePath);
            
            File destinationFile = new File(encryptionFilePath);
            
            writeDataToFile(destinationFile ,encript(extractDataFromFile(originalFile)));
            
            String fileName = originalFile.getName().split("\\.(?=[^\\.]+$)")[0];
            
            
            byte[] metadataContent = createMetadataFile(metadataKeywords);
            if(metadataContent != null){
                
                String metadataFilePath = encryptionPathFolder +  System.getProperty("file.separator") + fileName + ".metadata";
                
                writeDataToFile(new File(metadataFilePath), metadataContent);
                
            }
            
            return true;
        } catch (Exception ex){
            return false;
        }
    }
    
    
    public boolean encriptAndSignFile(String filePath, String encriptionPathFolder){
        return true;
    }
    
    public boolean signFile(String filePath, String encriptionPathFolder){
        return true;
    }
       
    
    
    private byte[] createMetadataFile(String keywords) throws ParserConfigurationException, SAXException, IOException, TransformerConfigurationException, TransformerException{
        
        String[] splittedKeywords =  keywords.split(";");
        
        if(splittedKeywords.length == 0 || keywords.equals("")){
            return null;
        }
        
        String fakeXML = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?><metadata></metadata>";
        InputStream is = new ByteArrayInputStream(fakeXML.getBytes());
        StringWriter writer = new StringWriter();


        //Create the documentBuilderFactory and documentBuilder
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(is);

        //Get the root element of the xml Document;
        Element documentElement = document.getDocumentElement();


        //add keywords
        for(String keyword: splittedKeywords){
            Element keywordNode = document.createElement("keyword");
            keywordNode.setTextContent(keyword);
            documentElement.appendChild(keywordNode);
        }
        
        
        Transformer tFormer = TransformerFactory.newInstance().newTransformer();       
        tFormer.setOutputProperty(OutputKeys.METHOD, "xml");
        tFormer.setOutputProperty(OutputKeys.INDENT, "yes");

        //  Write the node to the string
        Source source = new DOMSource(documentElement);
        Result result = new StreamResult(writer);
        tFormer.transform(source, result);
        writer.close();

        String xml = writer.toString();
                
                
        return xml.getBytes();
        
    }
       
    
    private void writeDataToFile(File filePath, byte[] content) throws FileNotFoundException, IOException{
         FileOutputStream fos = new FileOutputStream(filePath);
         
         fos.write(content);
         
         fos.close();
    }
    
    private byte[] extractDataFromFile(File filePath) throws FileNotFoundException, IOException{
        
        
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
    
    
    
    
       
    
}
