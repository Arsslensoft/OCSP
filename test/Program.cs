using Al.Security.Asn1;
using Al.Security.Asn1.Ocsp;
using Al.Security.Asn1.X509;
using Al.Security.Crypto;
using Al.Security.Crypto.Parameters;
using Al.Security.Math;
using Al.Security.Ocsp;
using Al.Security.OpenSsl;
using Al.Security.Security;
using Al.Security.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using System.Text;
using System.Threading;

namespace test
{
   
    public class CertificateCrlValidator
    {
        public CertificateCrlValidator(string pfx)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 acertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfx, "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet);
            CACert = DotNetUtilities.FromX509Certificate(acertificate);
            // Now you have your private key in binary form as you wanted
            // You can use rsa.ExportParameters() or rsa.ExportCspBlob() to get you bytes
            // depending on format you need them in
            RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)acertificate.PrivateKey;

            // Just for lulz, let's write out the PEM representation of the private key
            // using Bouncy Castle, so that we are 100% sure that the result is exaclty the same as:
            // openssl pkcs12 -in filename.pfx -nocerts -out privateKey.pem
            // openssl.exe rsa -in privateKey.pem -out private.pem


            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            CAKey = keyPair.Private;
            Crl = null;


        }
        public CertificateCrlValidator(string pfx, string crl)
        {

            System.Security.Cryptography.X509Certificates.X509Certificate2 acertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(pfx, "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable | System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet);
            CACert = DotNetUtilities.FromX509Certificate(acertificate);
            // Now you have your private key in binary form as you wanted
            // You can use rsa.ExportParameters() or rsa.ExportCspBlob() to get you bytes
            // depending on format you need them in
            RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)acertificate.PrivateKey;

            // Just for lulz, let's write out the PEM representation of the private key
            // using Bouncy Castle, so that we are 100% sure that the result is exaclty the same as:
            // openssl pkcs12 -in filename.pfx -nocerts -out privateKey.pem
            // openssl.exe rsa -in privateKey.pem -out private.pem

        
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            CAKey = keyPair.Private;
            Crl = new X509CrlParser().ReadCrl(File.ReadAllBytes(crl));


        }
        public X509Crl Crl;
        public X509Certificate CACert;
        public AsymmetricKeyParameter CAKey;
        public bool IsRevoked(CertificateID id, ref DerGeneralizedTime dt, ref CrlReason reason)
        {
            if (Crl == null)
                return false;
            else
            {
              X509CrlEntry ent =  Crl.GetRevokedCertificate(id.SerialNumber);
              if (ent == null)
                  return false;
              else
              {
                  dt = new DerGeneralizedTime(ent.RevocationDate);
                  reason = new CrlReason(CrlReason.CessationOfOperation);
                  return true;
              }

            }
        }
    }
    class OCSPCache
    {
        public byte[] data;
        public DateTime CacheTime;
    }
    public class Logger
    {
        public static void LogOCSP(string log)
        {

        }
    }
    public class OCSPServer : HttpServer
    {
        Dictionary<long, OCSPCache> Cache = new Dictionary<long, OCSPCache>();
      
        public OCSPServer(int port)
            : base(port)
        {
    
        }
        public override void handleGETRequest(HttpProcessor p)
        {
            if (p.http_url == "/")
            {
                p.writeSuccess();
                p.outputStream.WriteLine("<html><head><title>Arsslensoft Online Certificate Status Protocol Server</title></head><body><h1>ACCESS DENIED - Online Certificate Status Protocol</h1><p>This is the Arsslensoft OCSP Server Version 1.0 .</p></body></html>");
            }
            else if (p.http_url == "/ocsp?query=GET_SERVER_INFO&method=HTTP&user=arsslen&id=123")
            {
                p.writeSuccess();
                //StringBuilder sb = new StringBuilder();
                //sb.Append("<html><head>");
                //sb.Append("<title>OCSP STATUS</title>");
                //sb.Append("</head><body>");
                //sb.Append("<h4>MEMORY STATUS</h4>");va
                //sb.Append("<p>Used Memory : "+ Process.GetCurrentProcess().WorkingSet64.ToString()+" bytes</p>");
            
                //sb.Append("</body></html>");
                //p.outputStream.WriteLine(sb.ToString());
                // TODO
            }
            else if (p.http_url.StartsWith("/ocsp?query=CERT_STATUS&serial="))
            {
                
            }
          
        }
        void AddCache(byte[] resp, long serial)
        {
            if (Cache.ContainsKey(serial))
            {
                OCSPCache c = new OCSPCache();
                c.data = resp;
                c.CacheTime = DateTime.Now;
                Cache[serial] = c;
            }
            else
            {
                OCSPCache c = new OCSPCache();
                c.data = resp;
                c.CacheTime = DateTime.Now;
                Cache.Add(serial,c);
            }
        }
        OCSPCache GetCache(long serial)
        {
            if (Cache.ContainsKey(serial))
            {
                // max cache time = 1 hour
                if (DateTime.Now.Subtract(Cache[serial].CacheTime).TotalHours >= Program.CacheHours)
                    return null;
                else return Cache[serial];
            }
            else return null;
        }
        public override void handlePOSTRequest(HttpProcessor p, MemoryStream ms)
        {

            try
            {
              

                byte[] ocspdata = ms.ToArray();
                OcspReq req = new OcspReq(ocspdata);
                GeneralName name = req.RequestorName;
                if (validator != null)
                {
                    string stat = "GOOD";
                    foreach (CertificateID id in req.GetIDs())
                    {
                        Stopwatch st = new Stopwatch();
                        st.Start();
                        OCSPCache cac = GetCache(id.SerialNumber.LongValue);
                        if (cac != null)
                        {
                            Console.Write("[CACHED] ");
                            string header = GetRFC822Date(cac.CacheTime);
                            byte[] responseBytes = cac.data;
                            p.outputStream.WriteLine("HTTP/1.1 200 OK");
                            p.outputStream.WriteLine("content-transfer-encoding: binary");
                            p.outputStream.WriteLine("Last-Modified: " + header);
                            p.outputStream.WriteLine("Content-Type: application/ocsp-response");
                            p.outputStream.WriteLine("Connection: keep-alive");
                            p.outputStream.WriteLine("Accept-Ranges: bytes");
                            p.outputStream.WriteLine("Server: AS-OCSP-1.0");
                            p.outputStream.WriteLine("Content-Length: " + responseBytes.Length.ToString());
                            p.outputStream.WriteLine("");
                            p.outputStream.WriteContent(responseBytes);
                        }
                        else
                        {
                            // validate
                            OCSPRespGenerator gen = new OCSPRespGenerator();

                            BasicOcspRespGenerator resp = new BasicOcspRespGenerator(validator.CACert.GetPublicKey());

                            DerGeneralizedTime dt = new DerGeneralizedTime(DateTime.Parse("03/09/2014 14:00:00"));
                            CrlReason reason = new CrlReason(CrlReason.CACompromise);
                      
                            if (validator.IsRevoked(id, ref dt, ref reason))
                            {
                                RevokedInfo rinfo = new RevokedInfo(dt, reason);
                                RevokedStatus rstatus = new RevokedStatus(rinfo);
                                resp.AddResponse(id, rstatus);
                                stat = "REVOKED";
                            }
                            else resp.AddResponse(id, CertificateStatus.Good);

                            BasicOcspResp response = resp.Generate("SHA1withRSA", validator.CAKey, new X509Certificate[] { validator.CACert }, DateTime.Now);
                            OcspResp or = gen.Generate(OCSPRespGenerator.Successful, response);
                            string header = GetRFC822Date(DateTime.Now);

                            byte[] responseBytes = or.GetEncoded();
                            AddCache(responseBytes, id.SerialNumber.LongValue);
                            p.outputStream.WriteLine("HTTP/1.1 200 OK");
                            p.outputStream.WriteLine("content-transfer-encoding: binary");
                            p.outputStream.WriteLine("Last-Modified: " + header);
                            p.outputStream.WriteLine("Content-Type: application/ocsp-response");
                            p.outputStream.WriteLine("Connection: keep-alive");
                            p.outputStream.WriteLine("Accept-Ranges: bytes");
                            p.outputStream.WriteLine("Server: AS-OCSP-1.0");
                            p.outputStream.WriteLine("Content-Length: " + responseBytes.Length.ToString());
                            p.outputStream.WriteLine("");
                            p.outputStream.WriteContent(responseBytes);
                        }
                        Console.Write(id.SerialNumber + " PROCESSED IN "+st.Elapsed + " STATUS "+ stat);
                        Console.WriteLine("");
                    }
                
                }
                else
                    p.writeFailure();
             
            }
            catch(Exception ex)
            {
                Console.WriteLine("OCSP Server Error : " + ex.Message);
               
            }
        }
        private string GetRFC822Date(DateTime date)
        {
            int offset = TimeZone.CurrentTimeZone.GetUtcOffset(DateTime.Now).Hours;
            string timeZone = "+" + offset.ToString().PadLeft(2, '0');

            if (offset < 0)
            {
                int i = offset * -1;
                timeZone = "-" + i.ToString().PadLeft(2, '0');
            }

            return date.ToString("ddd, dd MMM yyyy HH:mm:ss " + timeZone.PadRight(5, '0'));
        }
        public byte[] Append(byte[] data, byte[] arg)
        {
            byte[] a = new byte[data.Length + arg.Length];
            for (int i = 0; i < data.Length; i++)
                a[i] = data[i];

            for (int j = 0; j < arg.Length; j++)
                a[data.Length + j] = arg[j];

            return a;
        }
    }

    class Keys
    {
       
     public   static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            RsaPrivateCrtKeyParameters keyPair;

            using (var reader = File.OpenText(privateKeyFileName))
                keyPair = (RsaPrivateCrtKeyParameters)new PemReader(reader).ReadObject();
            var rsa = (AsymmetricKeyParameter)keyPair;
    

            return rsa;
        }
    }
    class Program
    {
        public static int Port = 1456;
        public static int CacheHours = 1;
        static string CAFile = "";
        static string CRL = "";
        static HttpServer httpServer;

        static void Main(string[] args)
        {
            try
            {
                foreach (string arg in args)
                {
                    if (arg.StartsWith("-cache:"))
                        CacheHours = int.Parse(arg.Replace("-cache:", ""));
                    else if (arg.StartsWith("-port:"))
                        Port = int.Parse(arg.Replace("-port:", ""));
                    else if (arg.StartsWith("-pfx:"))
                        CAFile = arg.Replace("-pfx:", "");
                    else if (arg.StartsWith("-crl:"))
                        CRL = arg.Replace("-crl:", "");
                }
                Console.WriteLine(CAFile);
                Console.WriteLine(Port);
               

                httpServer = new OCSPServer(Port);
                if (string.IsNullOrEmpty(CRL))
                    httpServer.validator = new CertificateCrlValidator(CAFile);
                else
                    httpServer.validator = new CertificateCrlValidator(CAFile, CRL);

                Thread thread = new Thread(new ThreadStart(httpServer.listen));
                thread.Start();
                Console.WriteLine("OCSP Server Started");
                System.Timers.Timer tm = new System.Timers.Timer();
                tm.Elapsed += TE;
                tm.Interval = CacheHours * 3600 * 1000;
             tm.Start();

             // sv = new OCSPServer();
                //sv.OnDataReceived += sv_OnDataReceived;
                //   sv.StartListening();
                //bool run = true;
                //while (run)
                //{
                //    Console.Write("Command : ");
                //    string cmd = Console.ReadLine();
                //    if (cmd == "quit")
                //        run = false;
                //    else if (cmd == "update")
                //    {
                //        if (string.IsNullOrEmpty(CRL))
                //            httpServer.validator = new CertificateCrlValidator(CAKey, CAFile);
                //        else
                //            httpServer.validator = new CertificateCrlValidator(CAKey, CAFile, CRL);
                //        Console.WriteLine("updated");
                //    }
                //}
                Console.Read();
            }
            catch (Exception ex)
            {
                
            }
        }
        static void TE(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(CRL))
                    httpServer.validator = new CertificateCrlValidator(CAFile);
                else
                    httpServer.validator = new CertificateCrlValidator(CAFile, CRL);
                Console.WriteLine("OCSP Data Updated");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to update OCSP Data");
                Console.WriteLine(ex.Message);
            }
        }
      
      
    }
}
