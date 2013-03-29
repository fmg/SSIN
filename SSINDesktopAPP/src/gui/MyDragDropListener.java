/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package gui;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.dnd.DropTargetEvent;
import java.awt.dnd.DropTargetListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.JTextField;

/**
 *
 * @author Desktop
 */
class MyDragDropListener implements DropTargetListener {
    
    
    EncriptionScreen guiScreen;
    JTextField dropFile_Tlabel;
    

    @Override
    public void drop(DropTargetDropEvent event) {

        // Accept copy drops
        event.acceptDrop(DnDConstants.ACTION_COPY);

        // Get the transfer which can provide the dropped item data
        Transferable transferable = event.getTransferable();

        // Get the data formats of the dropped item
        DataFlavor[] flavors = transferable.getTransferDataFlavors();

        // Loop through the flavors
        for (DataFlavor flavor : flavors) {

            try {

                // If the drop items are files
                if (flavor.isFlavorJavaFileListType()) {

                    // Get all of the dropped files
                    List<File> files = (List) transferable.getTransferData(flavor);

                    // Loop them through
                    for (File file : files) {

                        // Print out the file path
                        
                        if(!file.isDirectory()){
                        
                        System.out.println("File path is '" + file.getPath() + "'.");
                        dropFile_Tlabel.setText(file.getPath());
                        dropFile_Tlabel.setEnabled(true);
                        for(ActionListener a: dropFile_Tlabel.getActionListeners()) {
                            a.actionPerformed(new ActionEvent(this, ActionEvent.ACTION_PERFORMED, null) {
                                  //Nothing need go here, the actionPerformed method (with the
                                  //above arguments) will trigger the respective listener
                            });
                        }
                        }else{
                             System.out.println("Not a file");

                            JOptionPane.showMessageDialog(guiScreen,
                               "Must be a file",
                               "Error",
                               JOptionPane.ERROR_MESSAGE);

                           System.out.println("Not a file");
                        }
                    }

                }

            } catch (Exception e) {

                JOptionPane.showMessageDialog(guiScreen,
                               "Unexpected error occoured",
                               "Error",
                               JOptionPane.ERROR_MESSAGE);

            }
        }

        // Inform that the drop is complete
        event.dropComplete(true);

    }

    @Override
    public void dragEnter(DropTargetDragEvent event) {
    }

    @Override
    public void dragExit(DropTargetEvent event) {
    }

    @Override
    public void dragOver(DropTargetDragEvent event) {
    }

    @Override
    public void dropActionChanged(DropTargetDragEvent event) {
    }

    public MyDragDropListener(EncriptionScreen encriptionScreen, JTextField fileTF) {
        guiScreen = encriptionScreen;
        dropFile_Tlabel = fileTF;
        
    }

    
    
}
