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
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.smartcardio.CardException;
import javax.swing.JTextArea;
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
public class EncryptionModule {
    
    private static String TRIPLE_DES_TRANSFORMATION = "DESede/ECB/PKCS5Padding";
    private static String ALGORITHM = "DESede";
    private static String BOUNCY_CASTLE_PROVIDER = "BC";
    private static String HMAC_ALGORITHM = "HmacSHA256";

    private Cipher encrypter;
    private Cipher decrypter;
    private Mac signing;
    
    private static EncryptionModule encAPI;
    
    
    /**
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException 
     */
    private EncryptionModule() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException {
        
        Security.addProvider(new BouncyCastleProvider());
        encrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        decrypter = Cipher.getInstance(TRIPLE_DES_TRANSFORMATION, BOUNCY_CASTLE_PROVIDER);
        signing = Mac.getInstance(HMAC_ALGORITHM);
        
    }
    
    
    /**
     * 
     * @return
     * @throws Exception 
     */
    public static synchronized EncryptionModule getObjectInstance() throws Exception  {
        if (encAPI == null) {
                encAPI = new EncryptionModule();
        }
        return encAPI;
    }
    
    
    
    
    
    /********************************************
     *               Key Loading                *
     *******************************************/
    
    
    /**
     * 
     * @throws CardException
     * @throws Exception 
     */
    public void loadInformationFromCard() throws CardException, Exception {
        
        CardMediator cm = CardMediator.getObjectInstance();
                
        cm.openChannel();
        cm.selectApplet();
        
        
        List<SecretKey> keys = cm.getSecretKeys();
        
        encrypter.init(Cipher.ENCRYPT_MODE, keys.get(0));
        decrypter.init(Cipher.DECRYPT_MODE, keys.get(0));

        signing.init(keys.get(1));
        
        cm.closeChannel();

        
    }
    
    

    
    
    /********************************************
     *      Encyption and Signature signing     *
     *******************************************/
    
    
    /**
     * 
     * @param filePath
     * @param encryptionPathFolder
     * @param metadataKeywords
     * @param deleteFile
     * @param outputConsole
     * @return 
     */
    public boolean encryptFile(String filePath, String encryptionPathFolder, String metadataKeywords, boolean deleteFile, JTextArea outputConsole){
        try {
            outputConsole.setText("");
            outputConsole.append("Creating files:\n");
            
            
            File originalFile = new File(filePath);
            String encryptionFilePath = encryptionPathFolder +  System.getProperty("file.separator") + originalFile.getName();
            outputConsole.append(originalFile.getName() + "(Encrypted)\n");
            
            File destinationFile = new File(encryptionFilePath);
            
            writeDataToFile(destinationFile ,encript(extractDataFromFile(originalFile)));
            
            String fileName = originalFile.getName().split("\\.(?=[^\\.]+$)")[0];
            
            
            byte[] metadataContent = createMetadataFile(metadataKeywords);
            if(metadataContent != null){
                
                
                outputConsole.append(fileName + ".metadata\n");
                String metadataFilePath = encryptionPathFolder +  System.getProperty("file.separator") + fileName + ".metadata";             
                
                
                writeDataToFile(new File(metadataFilePath), metadataContent);
                
            }
            
            if(deleteFile){
                originalFile.delete();
                outputConsole.append("Deleted Original File");
            }
            
            outputConsole.append("Operation Completed");
            return true;
        } catch (Exception ex){
            outputConsole.append("Error!\n"+ ex.getMessage());
            return false;
        }
    }
    
    
    
    /**
     * 
     * @param filePath
     * @param encryptionPathFolder
     * @param metadataKeywords
     * @param deleteFile
     * @param outputConsole
     * @return 
     */
    public boolean encriptAndSignFile(String filePath, String encryptionPathFolder, String metadataKeywords, boolean deleteFile, JTextArea outputConsole){
        try {
            outputConsole.setText("");
            outputConsole.append("Creating files:\n");
            
            File originalFile = new File(filePath);
            byte[] originalFileContent = extractDataFromFile(originalFile);
            String fileName = originalFile.getName().split("\\.(?=[^\\.]+$)")[0];
            
            
            //encryption
            String encDestinationFile = encryptionPathFolder +  System.getProperty("file.separator") + originalFile.getName();
            outputConsole.append(originalFile.getName() + "(Encrypted)\n");
            File encrypdestinationFile = new File(encDestinationFile);
            writeDataToFile(encrypdestinationFile ,encript(originalFileContent));
            
            
            //signature
            String signatureFileName = encryptionPathFolder +  System.getProperty("file.separator") + fileName + ".signature";
            outputConsole.append(fileName + ".signature\n");
            File sigDestinationFile = new File(signatureFileName);
            writeDataToFile(sigDestinationFile ,sign(originalFileContent));
            
            
            byte[] metadataContent = createMetadataFile(metadataKeywords);
            if(metadataContent != null){
                
                outputConsole.append(fileName + ".metadata\n");
                String metadataFilePath = encryptionPathFolder +  System.getProperty("file.separator") + fileName + ".metadata";
                writeDataToFile(new File(metadataFilePath), metadataContent);
                
            }  
            
            if(deleteFile){
                originalFile.delete();
                outputConsole.append("Deleted Original File");
            }
            
            
            outputConsole.append("Operation Completed");
            return true;
        } catch (Exception ex){
            outputConsole.append("Error!\n"+ ex.getMessage());
            return false;
        }
    } 
    
    
    
    /**
     * 
     * @param filePath
     * @param encryptionPathFolder
     * @param outputConsole
     * @return 
     */
    public boolean signFile(String filePath, String encryptionPathFolder, JTextArea outputConsole){
        try {
            outputConsole.setText("");
            outputConsole.append("Creating files:\n");
            
            File originalFile = new File(filePath);
            
            String fileName = originalFile.getName().split("\\.(?=[^\\.]+$)")[0];
            outputConsole.append(fileName + ".signature\n");
            fileName = encryptionPathFolder +  System.getProperty("file.separator") + fileName + ".signature";

            
            File destinationFile = new File(fileName);
            writeDataToFile(destinationFile ,sign(extractDataFromFile(originalFile)));

            outputConsole.append("Operation Completed");
            return true;
        } catch (Exception ex){
            outputConsole.append("Error!\n"+ ex.getMessage());
            return false;
        }
    }
       
    
    
    
    
    /********************************************
     * Decryption and Signature verification    *
     *******************************************/
    
    /**
     * 
     * @param fileContent
     * @param signatureValue
     * @return 
     */
    private boolean verifySignature(byte[] fileContent, byte[] signatureValue){
        
        byte[] newSig = signing.doFinal(fileContent);
        
        return Arrays.equals(signatureValue, newSig);
    }

    
    
    /**
     * 
     * @param filePath
     * @param decryptionFolder
     * @param outputConsole
     * @return 
     */
    public boolean decryptAndVerify(String filePath, String decryptionFolder, JTextArea outputConsole){
        
        try {
            outputConsole.setText("");
            outputConsole.append("Creating files:\n");
            
            File originalFile = new File(filePath);
            
            String sigFileName = originalFile.getName().split("\\.(?=[^\\.]+$)")[0];
            sigFileName = originalFile.getParent()+ System.getProperty("file.separator") + sigFileName + ".signature";
 
            
            
            File signatureFile = new File(sigFileName);
            
            byte[] decryptedContent = decript(extractDataFromFile(originalFile));
            
            boolean valid = verifySignature(decryptedContent, extractDataFromFile(signatureFile));
            
            if(!valid){
                outputConsole.append("Invalid Signature. File was been tampered!\n");
                return false;
            }
            
            outputConsole.append("Valid Signature.\n");

            
            String decriptedFile = decryptionFolder + System.getProperty("file.separator") + originalFile.getName();
            
            writeDataToFile(new File(decriptedFile) ,decryptedContent);
            
            outputConsole.append(originalFile.getName() + "(Decrypted)\n");

            outputConsole.append("Operation Completed");
            return true;
        } catch (Exception ex){
            outputConsole.append("Error!\n"+ ex.getMessage());
            return false;
        }
        
    }
    
    
    
    /**
     * 
     * @param filePath
     * @param outputConsole
     * @return 
     */
    public boolean verifyFile(String filePath, JTextArea outputConsole){
        
        
        try {
            outputConsole.setText("");
            outputConsole.append("Checking file:\n");
            
            File originalFile = new File(filePath);
            
            String sigFileName = originalFile.getName().split("\\.(?=[^\\.]+$)")[0];
            sigFileName = originalFile.getParent()+ System.getProperty("file.separator") + sigFileName + ".signature";
 
            
            
            File signatureFile = new File(sigFileName);
            
            
            boolean valid = verifySignature(extractDataFromFile(originalFile), extractDataFromFile(signatureFile));
            
            if(!valid){
                outputConsole.append("Invalid Signature. File was been tampered!\n");
                return false;
            }
            
            outputConsole.append("Valid Signature.\n");


            outputConsole.append("Operation Completed");
            return true;
        } catch (Exception ex){
            outputConsole.append("Error!\n"+ ex.getMessage());
            return false;
        }
    }
    
    
    
    /**
     * 
     * @param filePath
     * @param decryptionFolder
     * @param outputConsole
     * @return 
     */
    public boolean decryptFile(String filePath, String decryptionFolder, JTextArea outputConsole){
         try {
            outputConsole.setText("");
            outputConsole.append("Creating files:\n");
            
            File originalFile = new File(filePath);
            byte[] decryptedContent = decript(extractDataFromFile(originalFile));
  
            String decriptedFile = decryptionFolder + System.getProperty("file.separator") + originalFile.getName();
            
            writeDataToFile(new File(decriptedFile) ,decryptedContent);
            
            outputConsole.append(originalFile.getName() + "(Decrypted)\n");

            outputConsole.append("Operation Completed");
            return true;
        } catch (Exception ex){
            outputConsole.append("Error!\n"+ ex.getMessage());
            return false;
        }
    }
    
    
    
    
    
    /************************************
     *              UTILS               *
    *************************************/
    
    
    /**
     * 
     * @param fileContent
     * @return 
     */
    private byte[] encript(byte[] fileContent){
        try {
            return encrypter.doFinal(fileContent);
        } catch(Exception ex){
            return new byte[0];
        }
        
    }
    
    
    
    /**
     * 
     * @param encriptedFileContent
     * @return 
     */
    private byte[] decript(byte[] encriptedFileContent){
        try {
            return decrypter.doFinal(encriptedFileContent);
        } catch (Exception ex) {
            return new byte[0];
        } 
    }
    
    
    
    /**
     * 
     * @param fileContent
     * @return 
     */
    private byte[] sign(byte[] fileContent){
        return signing.doFinal(fileContent);
    }
    
    
    
    /**
     * 
     * @param keywords
     * @return
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     * @throws TransformerConfigurationException
     * @throws TransformerException 
     */
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
    
    
    
    /**
     * 
     * @param filePath
     * @param content
     * @throws FileNotFoundException
     * @throws IOException 
     */
    private void writeDataToFile(File filePath, byte[] content) throws FileNotFoundException, IOException{
         FileOutputStream fos = new FileOutputStream(filePath);
         
         fos.write(content);
         
         fos.close();
    }
    
    
    
    /**
     * 
     * @param filePath
     * @return
     * @throws FileNotFoundException
     * @throws IOException 
     */
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
