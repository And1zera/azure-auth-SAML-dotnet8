using System.IO.Compression;
using System.Text;
using System.Xml;

namespace azure_auth_SAML_dotnet8
{
    public class SAMLAuthRequest
    {
        public string _id;
        private string _issue_instant;

        private string _issuer;
        private string _assertionConsumerServiceUrl;

        public enum AuthRequestFormat
        {
            Base64 = 1
        }

        public SAMLAuthRequest(string issuer, string assertionConsumerServiceUrl)
        {
            _id = "_" + Guid.NewGuid().ToString();
            _issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);

            _issuer = issuer;
            _assertionConsumerServiceUrl = assertionConsumerServiceUrl;
        }

        public string GetRequest(AuthRequestFormat format)
        {
            using (StringWriter sw = new StringWriter())
            {
                XmlWriterSettings xws = new XmlWriterSettings();
                xws.OmitXmlDeclaration = true;

                using (XmlWriter xw = XmlWriter.Create(sw, xws))
                {
                    xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("ID", _id);
                    xw.WriteAttributeString("Version", "2.0");
                    xw.WriteAttributeString("IssueInstant", _issue_instant);
                    xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                    xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

                    xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xw.WriteString(_issuer);
                    xw.WriteEndElement();

                    xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                    xw.WriteAttributeString("AllowCreate", "true");
                    xw.WriteEndElement();

                    xw.WriteEndElement();
                }

                if (format == AuthRequestFormat.Base64)
                {
                    var memoryStream = new MemoryStream();
                    var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
                    writer.Write(sw.ToString());
                    writer.Close();
                    string result = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
                    return result;
                }

                return null;
            }
        }

        //returns the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring
        public string GetRedirectUrl(string samlEndpoint, string relayState = null)
        {
            var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";

            var url = samlEndpoint + queryStringSeparator + "SAMLRequest=" + Uri.EscapeDataString(GetRequest(AuthRequestFormat.Base64));

            if (!string.IsNullOrEmpty(relayState))
            {
                url += "&RelayState=" + Uri.EscapeDataString(relayState);
            }

            return url;
        }
    }
}
