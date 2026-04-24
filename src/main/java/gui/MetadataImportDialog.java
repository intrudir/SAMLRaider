package gui;

import burp.BurpExtender;
import helpers.MetadataImport;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.Optional;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/// Dialog that accepts either a URL to fetch metadata XML from, or a pasted
/// XML blob. Returns the raw metadata XML to the caller; extraction happens
/// downstream in SamlTabController.importMetadata.
public class MetadataImportDialog {

    private MetadataImportDialog() {}

    public static Optional<String> prompt(Component parent) {
        var urlField = new JTextField(40);
        var fetchButton = new JButton("Fetch");
        var xmlArea = new JTextArea(18, 70);
        xmlArea.setLineWrap(false);
        var xmlScroll = new JScrollPane(xmlArea);
        xmlScroll.setPreferredSize(new Dimension(700, 360));

        fetchButton.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                JOptionPane.showMessageDialog(parent, "Enter a metadata URL first.",
                        "Metadata Import", JOptionPane.WARNING_MESSAGE);
                return;
            }
            try {
                String body = MetadataImport.fetch(url);
                xmlArea.setText(body);
                xmlArea.setCaretPosition(0);
            } catch (Exception ex) {
                BurpExtender.api.logging().logToError(ex);
                JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor((Component) e.getSource()),
                        "Fetch failed: " + ex.getMessage(),
                        "Metadata Import", JOptionPane.ERROR_MESSAGE);
            }
        });

        var urlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        urlRow.add(new JLabel("URL:"));
        urlRow.add(urlField);
        urlRow.add(fetchButton);

        var panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        panel.add(urlRow, BorderLayout.NORTH);
        panel.add(new JLabel("Metadata XML (paste or fetch):"), BorderLayout.CENTER);
        panel.add(xmlScroll, BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(
                parent, panel, "Metadata Import", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return Optional.empty();

        String xml = xmlArea.getText().trim();
        if (xml.isEmpty()) return Optional.empty();
        return Optional.of(xml);
    }
}
