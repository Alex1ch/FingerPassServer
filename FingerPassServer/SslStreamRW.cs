using System;
using System.Text;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Net;

namespace FingerPassServer
{
    class SslStreamRW
    {
        TcpClient client;
        SslStream sslStream;

        long id;
        string ip;
        int secTimeOut;
        string disconnectionReason="Unknown reason";
        bool alive;

        static long id_pool = 0;

        public string Ip { get => ip; set => ip = value; }
        public long Id { get => id; set => id = value; }
        public int SecTimeOut { get => secTimeOut; set => secTimeOut = value; }
        public string DisconnectionReason { get => disconnectionReason; set => disconnectionReason = value; }
        public bool Alive { get => alive; set => alive = value; }

        public string GetIpFormated() {

            return "(" + Ip + ","+id.ToString()+")  ";
        }

        public SslStreamRW(TcpClient _client, string servername)
        {
            client = _client;
            id = id_pool++;
            ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

            sslStream = new SslStream(client.GetStream(), true);
            sslStream.AuthenticateAsClient(servername);

            secTimeOut = 120;
            alive = true;
        }

        public SslStreamRW(TcpClient _client, X509Certificate2 cert)
        {
            client = _client;
            id = id_pool++;
            ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

            sslStream = new SslStream(client.GetStream(), true);
            sslStream.AuthenticateAsServer(cert, false, SslProtocols.Tls, true);

            secTimeOut = 120;
            alive = true;
        }
        
        public void Disconnect()
        {
            Logger.Log(GetIpFormated() + "Send disconnection signal", 1);
            byte[] zero_length = new byte[2];
            zero_length[0] = 0;
            zero_length[1] = 0;
            sslStream.Write(zero_length, 0, zero_length.Length);
            sslStream.Write(zero_length, 0, zero_length.Length);
            Thread.Sleep(300);
            sslStream.Close();
            client.Close();
            alive = false;
        }

        public void Disconnect(string reason)
        {
            Logger.Log(GetIpFormated() + "Send disconnection signal", 1);
            byte[] zero_length = new byte[2];
            zero_length[0] = 0;
            zero_length[1] = 0;
            sslStream.Write(zero_length, 0, zero_length.Length);
            WriteString(reason);
            Thread.Sleep(300);
            sslStream.Close();
            client.Close();
            alive = false;
        }

        public void DisconnectNoMessage() {
            sslStream.Close();
            client.Close();
            alive = false;
        }

        public bool WriteBytes(byte[] message)
        {
            if (message.Length == 0)
            {
                Disconnect();
                return false;
            }
            byte[] concat = new byte[2 + message.Length];
            concat[0] = (byte)(message.Length >> 8);
            concat[1] = (byte)(message.Length);
            Buffer.BlockCopy(message, 0, concat, 2, message.Length);

            try
            {
                sslStream.Write(concat);
                sslStream.Flush();
                return true;
            }
            catch(Exception e)
            {
                Logger.Log(GetIpFormated() + "Error writing message: " +e.Message, 3);
                if (e.InnerException != null)
                {
                    Logger.Log(GetIpFormated() + "Inner exception: " + e.InnerException.Message, 3);
                }
                Disconnect();
                return false;
            }
        }

        public bool WriteString(string line)
        {
            if (line.Length == 0)
            {
                Disconnect();
                return false;
            }
            byte[] message = Encoding.UTF8.GetBytes(line);
            byte[] concat = new byte[2 + message.Length];
            concat[0] = (byte)(message.Length >> 8);
            concat[1] = (byte)(message.Length);
            Buffer.BlockCopy(message, 0, concat, 2, message.Length);
            try
            {
                sslStream.Write(concat);
                sslStream.Flush();
                return true;
            }
            catch (Exception e)
            {
                Logger.Log(GetIpFormated() + "Error writing message: " + e.Message, 3);
                if (e.InnerException != null)
                {
                    Logger.Log(GetIpFormated() + "Inner exception: " + e.InnerException.Message, 3);
                }
                Disconnect();
                return false;
            }
        }
        

        public bool ReadBytes(out byte[] message)
        {
            message = new byte[0];
            byte[] buffer;

            try
            {
                long start = DateTime.Now.Ticks;
                while (client.Available == 0)
                {
                    if (DateTime.Now.Ticks - start > secTimeOut * 10000000)
                    {
                        disconnectionReason = "Time Out";
                        throw new Exception("Disconnected due timeout");
                    }
                    Thread.Sleep(50);
                }

                byte[] lengthBytes = new byte[2];

                sslStream.Read(lengthBytes, 0, 2);

                if (!client.Connected) return false;
                int length = lengthBytes[0] * 256 + lengthBytes[1];
                if (length == 0)
                {
                    Logger.Log(GetIpFormated()+"Recieved disconnection signal",1);
                    sslStream.Read(lengthBytes, 0, lengthBytes.Length);
                    length = lengthBytes[0] * 256 + lengthBytes[1];
                    if (length != 0)
                    {
                        byte[] reason = new byte[length];
                        sslStream.Read(reason, 0, length);

                        StringBuilder reasonData = new StringBuilder();

                        Decoder decoder1 = Encoding.UTF8.GetDecoder();
                        char[] reason_chars = new char[decoder1.GetCharCount(reason, 0, length)];
                        decoder1.GetChars(reason, 0, length, reason_chars, 0);
                        reasonData.Append(reason_chars);
                        disconnectionReason = reasonData.ToString();
                    }
                    DisconnectNoMessage();
                    return false;
                }

                buffer = new byte[length];

                sslStream.Read(buffer, 0, length);
                
            }
            catch (Exception e)
            {
                Logger.Log(GetIpFormated() + "Error reading message: " + e.Message, 3);
                if (e.InnerException != null)
                {
                    Logger.Log(GetIpFormated()+"Inner exception: " + e.InnerException.Message, 3);
                }
                Disconnect();
                return false;
            }

            message = buffer;
            return true;
        }

        public bool ReadString(out string line)
        {
            line = "";
            StringBuilder messageData = new StringBuilder();
            int bytes;
            try
            {
                //I know it's very strange code, but ReadTimeout isn't working ;( 

                long start = DateTime.Now.Ticks;
                while (client.Available == 0)
                {
                    if (DateTime.Now.Ticks - start > secTimeOut * 10000000)
                    {
                        disconnectionReason = "Time Out";
                        throw new Exception("Disconnected due timeout");
                    }
                    Thread.Sleep(50);
                }

                byte[] lengthBytes = new byte[2];
                
                bytes = sslStream.Read(lengthBytes, 0, lengthBytes.Length);
                if (!client.Connected) return false;
                int length = lengthBytes[0] * 256 + lengthBytes[1];
                if (length == 0)
                {
                    Logger.Log(GetIpFormated() + "Recieved disconnection signal", 1);
                    bytes = sslStream.Read(lengthBytes, 0, lengthBytes.Length);
                    length = lengthBytes[0] * 256 + lengthBytes[1];
                    if (length != 0)
                    {
                        byte[] reason = new byte[length];
                        sslStream.Read(reason, 0, length);

                        StringBuilder reasonData = new StringBuilder();

                        Decoder decoder1 = Encoding.UTF8.GetDecoder();
                        char[] reason_chars = new char[decoder1.GetCharCount(reason, 0, length)];
                        decoder1.GetChars(reason, 0, length, reason_chars, 0);
                        reasonData.Append(reason_chars);
                        disconnectionReason = reasonData.ToString();
                    }
                    DisconnectNoMessage();
                    return false;
                }

                byte[] buffer = new byte[length];

                sslStream.Read(buffer, 0, length);

                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, length)];
                decoder.GetChars(buffer, 0, length, chars, 0);
                messageData.Append(chars);
            }
            catch (Exception e)
            {
                Logger.Log(GetIpFormated() + "Error reading message: " + e.Message, 3);
                if (e.InnerException != null)
                {
                    Logger.Log(GetIpFormated() + "Inner exception: " + e.InnerException.Message, 3);
                }
                Disconnect();
                return false;
            }

            line = messageData.ToString();
            return true;
        }
    }
}
