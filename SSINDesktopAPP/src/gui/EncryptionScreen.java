/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package gui;

import encriptionLogic.EncryptionModule;
import java.awt.dnd.DropTarget;
import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileFilter;

/**
 *
 * @author Desktop
 */
public class EncryptionScreen extends javax.swing.JFrame {

    private EncryptionModule encAPI;
    
    private int encryption_option;
    private int decryption_option;
    private final static int SIGNATURE_ONLY = 0;
    private final static int ENCRYPTION_ONLY = 1;
    private final static int ENCRYPTION_AND_SIGNATURE = 2;
    
    /**
     * Creates new form EncriptionScreen
     */
    public EncryptionScreen() {
        initComponents();
        encryptionDestinationFolder_TF.setText(System.getProperty("user.dir"));
        decryptionDestinationFolder_TF.setText(System.getProperty("user.dir"));
        
         // Create the drag and drop listener
        MyDragDropListener encDragDropListener = new MyDragDropListener(this, dropFile_TF);
        MyDragDropListener decDragDropListener = new MyDragDropListener(this, encDropFile_TF);
        
        // Connect the label with a drag and drop listener
        new DropTarget(dropFile_TF, encDragDropListener);
        new DropTarget(encDropFile_TF, decDragDropListener);
        try {
            encAPI = EncryptionModule.getObjectInstance();
        } catch (Exception ex) {
            Logger.getLogger(EncryptionScreen.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        encryption_option = SIGNATURE_ONLY;
        decryption_option = SIGNATURE_ONLY;
        
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        buttonGroup2 = new javax.swing.ButtonGroup();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        encryptionDestinationFolder_TF = new javax.swing.JTextField();
        encryptionDestinationFolder_Button = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        encJPanel = new javax.swing.JPanel();
        dropFile_TF = new javax.swing.JTextField();
        jPanel3 = new javax.swing.JPanel();
        enc_encsig_RB = new javax.swing.JRadioButton();
        enc_enconly_RB = new javax.swing.JRadioButton();
        enc_sigonly_RB = new javax.swing.JRadioButton();
        jPanel4 = new javax.swing.JPanel();
        metadataKeywords_TF = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        encrypt_Button = new javax.swing.JButton();
        jPanel5 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        enc_outputConsole_TA = new javax.swing.JTextArea();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        decryptionDestinationFolder_TF = new javax.swing.JTextField();
        decryptionDestinationFolder_Button = new javax.swing.JButton();
        decJPanel = new javax.swing.JPanel();
        encDropFile_TF = new javax.swing.JTextField();
        jPanel7 = new javax.swing.JPanel();
        dec_encsig_RB = new javax.swing.JRadioButton();
        dec_enc_RB = new javax.swing.JRadioButton();
        dec_sig_RB = new javax.swing.JRadioButton();
        decrypt_Button = new javax.swing.JButton();
        jPanel8 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        decryp_outputConsole_TA = new javax.swing.JTextArea();
        deleteOriFile_CKB = new javax.swing.JCheckBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setResizable(false);

        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Ecription Destination Folder");
        jLabel1.setEnabled(false);
        jLabel1.setFocusable(false);

        encryptionDestinationFolder_TF.setEditable(false);

        encryptionDestinationFolder_Button.setText("Select Destination Folder");
        encryptionDestinationFolder_Button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encryptionDestinationFolder_ButtonActionPerformed(evt);
            }
        });

        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("Encryption Options");
        jLabel2.setFocusable(false);

        encJPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Drag and Drop file here", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));
        encJPanel.setPreferredSize(new java.awt.Dimension(173, 116));

        dropFile_TF.setEditable(false);
        dropFile_TF.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        dropFile_TF.setText("Drop file here");
        dropFile_TF.setBorder(null);
        dropFile_TF.setEnabled(false);
        dropFile_TF.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dropFile_TFActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout encJPanelLayout = new javax.swing.GroupLayout(encJPanel);
        encJPanel.setLayout(encJPanelLayout);
        encJPanelLayout.setHorizontalGroup(
            encJPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(encJPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(dropFile_TF, javax.swing.GroupLayout.DEFAULT_SIZE, 141, Short.MAX_VALUE)
                .addContainerGap())
        );
        encJPanelLayout.setVerticalGroup(
            encJPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(encJPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(dropFile_TF)
                .addContainerGap())
        );

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Choose file sensitivity", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));

        buttonGroup1.add(enc_encsig_RB);
        enc_encsig_RB.setText("High (Encription and Signature)");
        enc_encsig_RB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enc_encsig_RBActionPerformed(evt);
            }
        });

        buttonGroup1.add(enc_enconly_RB);
        enc_enconly_RB.setText("Medium (Encription only)");
        enc_enconly_RB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enc_enconly_RBActionPerformed(evt);
            }
        });

        buttonGroup1.add(enc_sigonly_RB);
        enc_sigonly_RB.setSelected(true);
        enc_sigonly_RB.setText("Low (Signature only)");
        enc_sigonly_RB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enc_sigonly_RBActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(enc_encsig_RB)
                    .addComponent(enc_enconly_RB)
                    .addComponent(enc_sigonly_RB))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(enc_encsig_RB)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(enc_enconly_RB)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(enc_sigonly_RB)
                .addContainerGap(8, Short.MAX_VALUE))
        );

        jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Add File Metadata", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));
        jPanel4.setPreferredSize(new java.awt.Dimension(216, 116));

        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel3.setText("Add keywords separated by semicolon");

        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel6.setText("(Will only be created when encrypting)");
        jLabel6.setEnabled(false);
        jLabel6.setFocusable(false);

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(metadataKeywords_TF, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 249, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(metadataKeywords_TF, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6)
                .addContainerGap(25, Short.MAX_VALUE))
        );

        encrypt_Button.setText("Do it!");
        encrypt_Button.setEnabled(false);
        encrypt_Button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encrypt_ButtonActionPerformed(evt);
            }
        });

        jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Ouput Console", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));
        jPanel5.setMinimumSize(new java.awt.Dimension(241, 117));
        jPanel5.setPreferredSize(new java.awt.Dimension(241, 117));

        enc_outputConsole_TA.setEditable(false);
        enc_outputConsole_TA.setColumns(20);
        enc_outputConsole_TA.setFont(new java.awt.Font("Monospaced", 0, 10)); // NOI18N
        enc_outputConsole_TA.setRows(5);
        jScrollPane1.setViewportView(enc_outputConsole_TA);

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 281, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 79, Short.MAX_VALUE)
                .addContainerGap())
        );

        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setText("Decryption and Signature Verification Options");

        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel5.setText("Decription Destination Folder");
        jLabel5.setEnabled(false);
        jLabel5.setFocusable(false);

        decryptionDestinationFolder_TF.setEditable(false);

        decryptionDestinationFolder_Button.setText("Select Destination Folder");
        decryptionDestinationFolder_Button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptionDestinationFolder_ButtonActionPerformed(evt);
            }
        });

        decJPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Drag and Drop file here", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));
        decJPanel.setPreferredSize(new java.awt.Dimension(173, 116));

        encDropFile_TF.setEditable(false);
        encDropFile_TF.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        encDropFile_TF.setText("Drop file here");
        encDropFile_TF.setBorder(null);
        encDropFile_TF.setEnabled(false);
        encDropFile_TF.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encDropFile_TFActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout decJPanelLayout = new javax.swing.GroupLayout(decJPanel);
        decJPanel.setLayout(decJPanelLayout);
        decJPanelLayout.setHorizontalGroup(
            decJPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(decJPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(encDropFile_TF, javax.swing.GroupLayout.DEFAULT_SIZE, 141, Short.MAX_VALUE)
                .addContainerGap())
        );
        decJPanelLayout.setVerticalGroup(
            decJPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(decJPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(encDropFile_TF)
                .addContainerGap())
        );

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Options", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));
        jPanel7.setPreferredSize(new java.awt.Dimension(227, 116));

        buttonGroup2.add(dec_encsig_RB);
        dec_encsig_RB.setText("Decryption and Signature Verification");
        dec_encsig_RB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dec_encsig_RBActionPerformed(evt);
            }
        });

        buttonGroup2.add(dec_enc_RB);
        dec_enc_RB.setText("Decryption");
        dec_enc_RB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dec_enc_RBActionPerformed(evt);
            }
        });

        buttonGroup2.add(dec_sig_RB);
        dec_sig_RB.setSelected(true);
        dec_sig_RB.setText("Signature Verification");
        dec_sig_RB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dec_sig_RBActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(dec_encsig_RB, javax.swing.GroupLayout.DEFAULT_SIZE, 243, Short.MAX_VALUE)
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(dec_enc_RB)
                            .addComponent(dec_sig_RB))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(dec_encsig_RB)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(dec_enc_RB)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(dec_sig_RB)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        decrypt_Button.setText("Do it!");
        decrypt_Button.setEnabled(false);
        decrypt_Button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decrypt_ButtonActionPerformed(evt);
            }
        });

        jPanel8.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Output Console", javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION));
        jPanel8.setPreferredSize(new java.awt.Dimension(178, 116));

        decryp_outputConsole_TA.setEditable(false);
        decryp_outputConsole_TA.setColumns(20);
        decryp_outputConsole_TA.setFont(new java.awt.Font("Monospaced", 0, 10)); // NOI18N
        decryp_outputConsole_TA.setRows(5);
        jScrollPane2.setViewportView(decryp_outputConsole_TA);

        javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
        jPanel8.setLayout(jPanel8Layout);
        jPanel8Layout.setHorizontalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 288, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel8Layout.setVerticalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel8Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        deleteOriFile_CKB.setText("Delete original file");
        deleteOriFile_CKB.setEnabled(false);
        deleteOriFile_CKB.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteOriFile_CKBActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator1)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(encJPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(deleteOriFile_CKB)
                            .addComponent(encrypt_Button, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED, 10, Short.MAX_VALUE)
                        .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, 313, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 786, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(encryptionDestinationFolder_TF))
                        .addGap(18, 18, 18)
                        .addComponent(encryptionDestinationFolder_Button))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 794, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(25, 25, 25))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(decryptionDestinationFolder_TF)
                                .addGap(18, 18, 18)))
                        .addComponent(decryptionDestinationFolder_Button))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(decJPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, 267, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(decrypt_Button)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jPanel8, javax.swing.GroupLayout.PREFERRED_SIZE, 320, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jLabel2)
                .addGap(18, 18, 18)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encryptionDestinationFolder_TF, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(encryptionDestinationFolder_Button))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(deleteOriFile_CKB)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(encrypt_Button)
                        .addGap(63, 63, 63))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jPanel4, javax.swing.GroupLayout.DEFAULT_SIZE, 117, Short.MAX_VALUE)
                            .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(encJPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 117, Short.MAX_VALUE)
                            .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(18, 18, 18)))
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel4)
                .addGap(18, 18, 18)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(decryptionDestinationFolder_TF, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(decryptionDestinationFolder_Button))
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jPanel7, javax.swing.GroupLayout.DEFAULT_SIZE, 125, Short.MAX_VALUE)
                            .addComponent(decJPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 125, Short.MAX_VALUE)
                            .addComponent(jPanel8, javax.swing.GroupLayout.DEFAULT_SIZE, 125, Short.MAX_VALUE))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(decrypt_Button)
                        .addGap(63, 63, 63))))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void encryptionDestinationFolder_ButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptionDestinationFolder_ButtonActionPerformed
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(encryptionDestinationFolder_TF.getText()));
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setApproveButtonText("Select Folder");



        FileFilter filter = new FileFilter() {

            @Override
            public boolean accept(File pathname) {
                return pathname.isDirectory();
            }

            @Override
            public String getDescription() {
                return "Folder";
            }
        };

        chooser.setFileFilter(filter);

        int r = chooser.showOpenDialog(this);
        if (r == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getPath();
            encryptionDestinationFolder_TF.setText(path);
        }
    }//GEN-LAST:event_encryptionDestinationFolder_ButtonActionPerformed

    private void dropFile_TFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dropFile_TFActionPerformed
        
        encrypt_Button.setEnabled(true);
    }//GEN-LAST:event_dropFile_TFActionPerformed

    private void encrypt_ButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encrypt_ButtonActionPerformed
              
        boolean success = false;
        boolean deleteFile = deleteOriFile_CKB.isSelected();
        
        
        switch(encryption_option){
            
            case SIGNATURE_ONLY:    success = encAPI.signFile(dropFile_TF.getText(), encryptionDestinationFolder_TF.getText(), enc_outputConsole_TA);
                                    break;
                
            case ENCRYPTION_ONLY:   success = encAPI.encryptFile(dropFile_TF.getText(), encryptionDestinationFolder_TF.getText(), metadataKeywords_TF.getText(), deleteFile, enc_outputConsole_TA);
                                    break;
                
            case ENCRYPTION_AND_SIGNATURE:  success = encAPI.encriptAndSignFile(dropFile_TF.getText(), encryptionDestinationFolder_TF.getText(), metadataKeywords_TF.getText(), deleteFile, enc_outputConsole_TA);
                                            break;
            
            default: break;
        }
        
        if(success){
            JOptionPane.showMessageDialog(this,
                               "Operation Completed.\n",
                               "Success",
                               JOptionPane.INFORMATION_MESSAGE);
        }else{
            JOptionPane.showMessageDialog(this,
                               "Error while doing operation.\n",
                               "Error",
                               JOptionPane.ERROR_MESSAGE);
        }
        
    }//GEN-LAST:event_encrypt_ButtonActionPerformed

    private void enc_sigonly_RBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enc_sigonly_RBActionPerformed
        encryption_option = SIGNATURE_ONLY;
        deleteOriFile_CKB.setSelected(false);
        deleteOriFile_CKB.setEnabled(false);

    }//GEN-LAST:event_enc_sigonly_RBActionPerformed

    private void enc_enconly_RBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enc_enconly_RBActionPerformed
        encryption_option = ENCRYPTION_ONLY;
        deleteOriFile_CKB.setSelected(true);
        deleteOriFile_CKB.setEnabled(true);
    }//GEN-LAST:event_enc_enconly_RBActionPerformed

    private void enc_encsig_RBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enc_encsig_RBActionPerformed
        encryption_option = ENCRYPTION_AND_SIGNATURE;
        deleteOriFile_CKB.setSelected(true);
        deleteOriFile_CKB.setEnabled(true);
    }//GEN-LAST:event_enc_encsig_RBActionPerformed

    private void encDropFile_TFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encDropFile_TFActionPerformed
        decrypt_Button.setEnabled(true);
    }//GEN-LAST:event_encDropFile_TFActionPerformed

    private void dec_encsig_RBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dec_encsig_RBActionPerformed
        decryption_option = ENCRYPTION_AND_SIGNATURE;
    }//GEN-LAST:event_dec_encsig_RBActionPerformed

    private void dec_enc_RBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dec_enc_RBActionPerformed
        decryption_option = ENCRYPTION_ONLY;
    }//GEN-LAST:event_dec_enc_RBActionPerformed

    private void dec_sig_RBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dec_sig_RBActionPerformed
        decryption_option = SIGNATURE_ONLY;
    }//GEN-LAST:event_dec_sig_RBActionPerformed

    private void decrypt_ButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decrypt_ButtonActionPerformed
        
        boolean success = false;
        
        switch(decryption_option){
            
            case SIGNATURE_ONLY:    success = encAPI.verifyFile(encDropFile_TF.getText(), decryp_outputConsole_TA);
                                    break;
                
            case ENCRYPTION_ONLY:   success = encAPI.decryptFile(encDropFile_TF.getText(), decryptionDestinationFolder_TF.getText(), decryp_outputConsole_TA);
                                    break;
                
            case ENCRYPTION_AND_SIGNATURE:  success = encAPI.decryptAndVerify(encDropFile_TF.getText(), decryptionDestinationFolder_TF.getText(), decryp_outputConsole_TA);
                                            break;
            
            default: break;
        }
        
        if(success){
            JOptionPane.showMessageDialog(this,
                               "Operation Completed.\n",
                               "Success",
                               JOptionPane.INFORMATION_MESSAGE);
        }else{
            JOptionPane.showMessageDialog(this,
                               "Error while doing operation.\nSee ouput for details.",
                               "Error",
                               JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_decrypt_ButtonActionPerformed

    private void decryptionDestinationFolder_ButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptionDestinationFolder_ButtonActionPerformed
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(encryptionDestinationFolder_TF.getText()));
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setApproveButtonText("Select Folder");



        FileFilter filter = new FileFilter() {

            @Override
            public boolean accept(File pathname) {
                return pathname.isDirectory();
            }

            @Override
            public String getDescription() {
                return "Folder";
            }
        };

        chooser.setFileFilter(filter);

        int r = chooser.showOpenDialog(this);
        if (r == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getPath();
            decryptionDestinationFolder_TF.setText(path);
        }
    }//GEN-LAST:event_decryptionDestinationFolder_ButtonActionPerformed

    private void deleteOriFile_CKBActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteOriFile_CKBActionPerformed

        
        
    }//GEN-LAST:event_deleteOriFile_CKBActionPerformed

    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.ButtonGroup buttonGroup2;
    private javax.swing.JPanel decJPanel;
    private javax.swing.JRadioButton dec_enc_RB;
    private javax.swing.JRadioButton dec_encsig_RB;
    private javax.swing.JRadioButton dec_sig_RB;
    private javax.swing.JTextArea decryp_outputConsole_TA;
    private javax.swing.JButton decrypt_Button;
    private javax.swing.JButton decryptionDestinationFolder_Button;
    private javax.swing.JTextField decryptionDestinationFolder_TF;
    private javax.swing.JCheckBox deleteOriFile_CKB;
    private javax.swing.JTextField dropFile_TF;
    private javax.swing.JTextField encDropFile_TF;
    private javax.swing.JPanel encJPanel;
    private javax.swing.JRadioButton enc_enconly_RB;
    private javax.swing.JRadioButton enc_encsig_RB;
    private javax.swing.JTextArea enc_outputConsole_TA;
    private javax.swing.JRadioButton enc_sigonly_RB;
    private javax.swing.JButton encrypt_Button;
    private javax.swing.JButton encryptionDestinationFolder_Button;
    private javax.swing.JTextField encryptionDestinationFolder_TF;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTextField metadataKeywords_TF;
    // End of variables declaration//GEN-END:variables
}
