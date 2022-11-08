package security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.swing.*;

public class MainForm {
    private JPanel panel1;
    private JTextArea textArea;
    private JRadioButton stringHash;
    private JRadioButton fileValidation;
    private JRadioButton fileHash;
    private JTextField filePathField;
    private JTextField hashField;
    private JButton runButton;
    private JButton clearButton;
    private JButton saveToFileButton;
    private JLabel fileLabel;
    private JLabel hashLabel;

    public static void main(String[] args) {
        JFrame frame = new JFrame("MD5");
        var form = new MainForm();
        frame.setContentPane(form.panel1);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);

        ButtonGroup group = new ButtonGroup();
        group.add(form.stringHash);
        group.add(form.fileValidation);
        group.add(form.fileHash);
        form.fileHash.setSelected(true);

        form.fileLabel.setVisible(false);
        form.filePathField.setVisible(false);

        form.clearButton.addActionListener(e -> form.textArea.setText(""));
        form.saveToFileButton.addActionListener(e -> {
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy_MM_dd HH_mm_ss");
            LocalDateTime now = LocalDateTime.now();
            try {
                FileWriter myObj = new FileWriter("C:\\Users\\vkind\\Desktop\\" + dtf.format(now) + " result.txt");
                myObj.write(form.textArea.getText());
                myObj.close();
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(frame, "Some problems with writing to file occurs",
                        "MD5 Algorithm", JOptionPane.ERROR_MESSAGE);
            }
        });

        form.stringHash.addActionListener(e -> {
            form.fileLabel.setVisible(false);
            form.filePathField.setVisible(false);
            form.hashLabel.setVisible(true);
            form.hashField.setVisible(true);
            form.hashLabel.setText("String to hash");
        });

        form.fileHash.addActionListener(e -> {
            form.fileLabel.setVisible(true);
            form.filePathField.setVisible(true);
            form.hashLabel.setVisible(false);
            form.hashField.setVisible(false);
            form.hashLabel.setText("File to hash");
        });

        form.fileValidation.addActionListener(e -> {
            form.fileLabel.setVisible(true);
            form.filePathField.setVisible(true);
            form.hashLabel.setVisible(true);
            form.hashField.setVisible(true);
            form.hashLabel.setText("Hash to validate");
        });

        form.runButton.addActionListener(e -> {
            if (form.stringHash.isSelected()) {
                String stringToHash = form.hashField.getText();
                String result = MD5.getHashString(stringToHash);
                form.textArea.append("MD5 hash from \"" + stringToHash + "\": " + result + "\n\n");
            } else if (form.fileHash.isSelected()) {
                String filePath = form.filePathField.getText();
                try {
                    String result = MD5.getHashString(new File(filePath));
                    form.textArea.append("MD5 hash from \"" + filePath + "\": " + result + "\n\n");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            } else {
                String filePath = form.filePathField.getText();
                String expectedHashFile = form.hashField.getText();
                try {
                    BufferedReader br = new BufferedReader(new FileReader(expectedHashFile));
                    String expectedHash = br.readLine();
                    expectedHash = expectedHash.substring(0, expectedHash.indexOf(" "));

                    String result = MD5.getHashString(new File(filePath));
                    form.textArea.append("The expected value: \"" + expectedHash + "\"\n");
                    form.textArea.append("MD5 hash from \"" + filePath + "\": \"" + result + "\"\n");
                    form.textArea.append(expectedHash.equals(result) ? "The file is valid\n\n" : "The file isn't valid\n\n");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });
    }
}
