package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/// Parses SAML 2.0 metadata (IdP or SP EntityDescriptor) and pulls every
/// embedded X.509 certificate out of <md:KeyDescriptor>. Certificates are
/// returned as base64-DER strings ready to feed into
/// CertificateTabController.importCertificateFromString.
///
/// Typical workflow per the KazHackStan deck: fetch `<host>/idp/metadata`
/// (or the SP equivalent), extract the signing cert, then use it for
/// certificate-faking / Dupe-Key Confusion.
public class MetadataImport {

    /// One parsed cert entry. `use` is "signing", "encryption", or "" if
    /// the KeyDescriptor did not declare a use.
    public record Entry(String use, String base64Der) {}

    /// Extract all X509Certificate bodies from a metadata XML string.
    public static List<Entry> extract(String metadataXml) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(metadataXml);

        List<Entry> out = new ArrayList<>();
        NodeList keyDescs = document.getElementsByTagNameNS("*", "KeyDescriptor");
        for (int i = 0; i < keyDescs.getLength(); i++) {
            Element kd = (Element) keyDescs.item(i);
            String use = kd.getAttribute("use"); // may be ""
            NodeList certs = kd.getElementsByTagNameNS("*", "X509Certificate");
            for (int j = 0; j < certs.getLength(); j++) {
                String text = certs.item(j).getTextContent();
                if (text != null && !text.isBlank()) {
                    out.add(new Entry(use, text.replaceAll("\\s+", "")));
                }
            }
        }
        return out;
    }

    /// Fetch metadata XML over HTTP(S) with a short timeout. The caller is
    /// expected to validate the URL — this is a pentester tool, so we do not
    /// enforce schemes or domains.
    public static String fetch(String url) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("User-Agent", "SAMLRaider/metadata-import")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("Metadata fetch returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    private MetadataImport() {}
}
