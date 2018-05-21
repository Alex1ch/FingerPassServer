using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.IO;
using System.Threading;
using Npgsql;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Prng;

namespace FingerPassServer
{
    class Server
    {
        static X509Certificate2 serverCertificate = null;
        static TcpListener sslOutListener;
        static TcpListener frontListener;
        static string frontAddress= "127.0.0.1";
        static bool alive;
        string sqlUser = "fingerpassserver";
        string sqlPass = "matrixislayered";
        string sqlName = "fingerpassserverdb";
        static NpgsqlConnectionStringBuilder stringBuilder;
        static Dictionary<string, bool> requestPool = new Dictionary<string, bool>();

        static NpgsqlConnection conn;

        static List<Task> tasks = new List<Task>();

        public static bool Alive { get => alive; set => alive = value; }

        static string CleanUpTasks(List<Task> tasks) {
            int count=0, active=0, cleaned=0;

            List<Task> toDispose = new List<Task>();

            count=tasks.Count;
            foreach (Task task in tasks) {
                if (task.Status == TaskStatus.Running) active++;
                if (task.Status == TaskStatus.RanToCompletion || task.Status == TaskStatus.Canceled || task.Status == TaskStatus.Faulted) {
                    toDispose.Add(task);
                }
            }

            foreach (Task task in toDispose)
            {
                tasks.Remove(task);
                task.Dispose();
                cleaned++;
            }
            toDispose = null;

            return String.Format("Count: {0}, Active: {1}, Cleaned: {2}", count, active, cleaned);
        }

        //Serve for auth from front
        Task ListenFront = new Task(() => {
            Logger.Log("Front listener is started", 1);

            byte[] approve = new byte[32];
            byte[] message = Encoding.UTF8.GetBytes("<APPROVED>");
            Buffer.BlockCopy(message,0,approve,0,message.Length);
            
            byte[] reject = new byte[32];
            message = Encoding.UTF8.GetBytes("<REJECT>");
            Buffer.BlockCopy(message, 0, reject, 0, message.Length);
            
            byte[] multiple_requests = new byte[32];
            message = Encoding.UTF8.GetBytes("<MULTIPLE>");
            Buffer.BlockCopy(message, 0, multiple_requests, 0, message.Length);

            while (alive) {
                TcpClient client = frontListener.AcceptTcpClient();
                NetworkStream stream = new NetworkStream(client.Client);
                StreamReader sReader = new StreamReader(stream);
                StreamWriter sWriter = new StreamWriter(stream);

                string ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

                if (ip != frontAddress)
                {
                    Logger.Log("Request from incorrect front ip (" + ip + ")", 3);
                    break;
                }

                Task.Factory.StartNew(() => {
                    switch (sReader.ReadLine()) {
                        case "REQUEST AUTH":
                            {
                                string user = sReader.ReadLine();
                                Logger.Log("Recieved auth signal from user '"+user+"'", 0);

                                if (requestPool.ContainsKey(user)) {
                                    requestPool.Remove(user);
                                    stream.Write(multiple_requests, 0, multiple_requests.Length);
                                    break;
                                }

                                requestPool.Add(user, false);
                                bool result;
                                for (int i = 0; i < 30; i++) {
                                    Thread.Sleep(1000);
                                    if (requestPool.TryGetValue(user, out result))
                                    {
                                        if (result == true)
                                        {
                                            requestPool.Remove(user);
                                            stream.Write(approve, 0, approve.Length);
                                            break;
                                        }
                                    }
                                    else {
                                        stream.Write(multiple_requests, 0, multiple_requests.Length);
                                        break;
                                    }
                                }
                                requestPool.Remove(user);
                                stream.Write(reject, 0, reject.Length);
                                break;
                            }
                        case "DELETE DEVICE":
                            {
                                string user = sReader.ReadLine();
                                Logger.Log("Recieved auth signal from user '" + user + "'", 0);

                                if (requestPool.ContainsKey(user))
                                {
                                    requestPool.Remove(user);
                                    stream.Write(multiple_requests, 0, multiple_requests.Length);
                                    break;
                                }

                                requestPool.Add(user, false);
                                bool result;
                                for (int i = 0; i < 30; i++)
                                {
                                    Thread.Sleep(1000);
                                    if (requestPool.TryGetValue(user, out result))
                                    {
                                        if (result == true)
                                        {
                                            requestPool.Remove(user);
                                            try
                                            {
                                                conn.Open();
                                                var user_raw = new NpgsqlCommand("SELECT id FROM auth_user WHERE username = '" + user + "'", conn).ExecuteScalar().ToString();
                                                Console.WriteLine("DELETE FROM devices WHERE user_id=" + user_raw);
                                                new NpgsqlCommand("DELETE FROM devices WHERE user_id=" + user_raw, conn).ExecuteNonQuery();
                                            }
                                            catch
                                            {
                                                stream.Write(reject, 0, reject.Length);
                                            }
                                            finally {
                                                conn.Close();
                                            }
                                            stream.Write(approve, 0, approve.Length);
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        stream.Write(multiple_requests, 0, multiple_requests.Length);
                                        break;
                                    }
                                }
                                requestPool.Remove(user);
                                stream.Write(reject, 0, reject.Length);
                                break;
                            }
                        default: break;
                    }
                });
            }
        });

        //Listen commands from Android app
        Task ListenSslConnection = new Task(() => {
            Logger.Log("Ssl server is started",1);

            while (alive) {
                TcpClient client = sslOutListener.AcceptTcpClient();
                
                CleanUpTasks(tasks);

                    Task clientHandler = new Task(() => {
                        SslStreamRW sslStreamRW = new SslStreamRW(client, serverCertificate);
                        try
                        {

                            Logger.Log(sslStreamRW.GetIpFormated() + "TCP Client connected ",1);

                            string message;

                            while (sslStreamRW.Alive&&alive)
                            {
                                if (sslStreamRW.ReadString(out message))
                                {
                                    if(message.Length!=0)
                                        Logger.Log(sslStreamRW.GetIpFormated()+"Recieved message: " + message);
                                    if (message == "<HANDSHAKE>") {
                                        Assign(sslStreamRW);
                                    }
                                    if (message == "<AUTH>") {
                                        Auth(sslStreamRW);
                                        
                                    }
                                }
                                else
                                {
                                    break;
                                }
                            }

                        }
                        catch(Exception e)
                        {
                            sslStreamRW.Disconnect("Serverside error ("+sslStreamRW.Id+")");
                            Logger.Log("Exception: "+ e.Message,3);
                            if (e.InnerException != null)
                            {
                                Logger.Log("Inner exception: " + e.InnerException.Message,3);
                            }
                            return;
                        }
                    });

                    clientHandler.Start();
                    tasks.Add(clientHandler);

                }
            });

        //Device assign function
        static bool Assign(SslStreamRW sslStreamRw) {

            string login, password, device_open_key,  device_name, IMEI;
            if (!sslStreamRw.ReadString(out login)) return false;
            if (!sslStreamRw.ReadString(out device_name)) return false;
            if (!sslStreamRw.ReadString(out IMEI)) return false;

            string salt, rounds, hash, user_id;
            login = login.Replace("'", "");

            var connection = new NpgsqlConnection(stringBuilder.ToString());

            connection.Open();
            //Checking device
            try
            {
                string[] splits;
                var user_raw = new NpgsqlCommand("SELECT id FROM auth_user WHERE username = '" + login + "'", connection).ExecuteScalar();
                if (user_raw == null)
                {
                    Logger.Log(sslStreamRw.GetIpFormated() + "User wasn't found ("+login+")");
                    sslStreamRw.Disconnect("User wasn't found");
                    connection.Close();
                    return false;
                }
                else {
                    Logger.Log(sslStreamRw.GetIpFormated() + "Login: " + login);
                }
                user_id = user_raw.ToString();
                splits = new NpgsqlCommand("SELECT password FROM auth_user WHERE username = '" + login + "'", connection).ExecuteScalar().ToString().Split('$');

                if (new NpgsqlCommand("SELECT * FROM devices WHERE user_id = " + user_id, connection).ExecuteScalar() != null)
                {
                    Logger.Log(sslStreamRw.GetIpFormated() + "This user already assign device");
                    sslStreamRw.Disconnect("This user already assign device, use safety code or delete device in your account");
                    return false;
                }
               
                if (new NpgsqlCommand("SELECT * FROM devices WHERE imei = '" + IMEI + "'", connection).ExecuteScalar() != null)
                {
                    Logger.Log(sslStreamRw.GetIpFormated() + "This device already assigned");
                    sslStreamRw.Disconnect("This device already assigned");
                    return false;
                }

                hash = splits[3];
                salt = splits[2];
                rounds = splits[1];
            }
            catch (Exception e)
            {
                Logger.Log(sslStreamRw.GetIpFormated() + "Error in sql request:\n" + e.Message,3);
                if (e.InnerException != null)
                {
                    Logger.Log(sslStreamRw.GetIpFormated() + "Inner exception: "+ e.InnerException.Message,3);
                }
                
                connection.Close(); 
                sslStreamRw.Disconnect("Serverside error\nid = "+sslStreamRw.Id);
                return false;
            }
            
            //Checking password
            if (!sslStreamRw.ReadString(out password)) return false;
            
            if (HashFuncs.PBKDF2Sha256GetBytes(32, password, salt, Int32.Parse(rounds)) != hash)
            {
                Logger.Log("Wrong password");
                sslStreamRw.Disconnect("Wrong password");
                return false;
            }
            
            if (!sslStreamRw.ReadString(out device_open_key)) return false;

            Logger.Log(String.Format(sslStreamRw.GetIpFormated() + "Device Name: {0}({1})\nRecieved device open key: {2}", device_name, IMEI, device_open_key));

            var restore = ((((ulong)new Org.BouncyCastle.Security.SecureRandom(new CryptoApiRandomGenerator()).NextLong())%90000000)+10000000).ToString();

            Logger.Log(sslStreamRw.GetIpFormated()+"Restore code is "+restore);
            //Adding device in database
            try
            {
                new NpgsqlCommand(String.Format("INSERT INTO devices (device_name,imei,restore_code,device_open_key,user_id) " +
                        "values ('{0}','" + IMEI + "','{1}','{2}','{3}');", device_name,restore, device_open_key, user_id), connection).ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Logger.Log(sslStreamRw.GetIpFormated() + "Error in sql insert:\n" + e.Message,3);
                if (e.InnerException != null)
                {
                    Logger.Log(sslStreamRw.GetIpFormated() + "Inner exception: " + e.InnerException.Message,3);
                }
                sslStreamRw.Disconnect("Something goes wrong in adding device");
                return false;
            }
            finally {
                connection.Close();
            }
            
            //Handshake successiful
            Logger.Log(sslStreamRw.GetIpFormated() + "Handshake successful");
            if (!sslStreamRw.WriteString("<ACCEPTED>")) return false;
            if (!sslStreamRw.WriteString(restore)) return false;
            return true;
        }








        static bool Auth(SslStreamRW sslStreamRW) {
            string login;
            if (!sslStreamRW.ReadString(out login)) { return false; };
            Logger.Log(sslStreamRW.GetIpFormated()+"Recieved auth signal from user '"+login+"'", 1);

            if (!requestPool.ContainsKey(login))
            {
                Logger.Log(sslStreamRW.GetIpFormated() + "No active authentication requests");
                sslStreamRW.Disconnect("No active authentication requests");
                return false;
            }

            login=login.Replace("'", "");

            string device_rsa_open_string;

            try
            {
                conn.Open();
                string id = new NpgsqlCommand("SELECT id FROM auth_user WHERE username = '" + login + "'", conn).ExecuteScalar().ToString();
                device_rsa_open_string=new NpgsqlCommand("SELECT device_open_key FROM devices WHERE user_id=" + id, conn).ExecuteScalar().ToString();

            }
            catch(Exception e)
            {
                Logger.Log(sslStreamRW.GetIpFormated()+"Error in user SQL request. Exception: "+e.Message+"; "+e.InnerException, 3);
                sslStreamRW.Disconnect("Serverside error\nid = "+sslStreamRW.Id+")");
                conn.Close();
                return false;
            }
            conn.Close();


            byte[] generated_bytes = new byte[192];
            Org.BouncyCastle.X509.X509Certificate gost_cert;

            try
            {
                gost_cert = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(device_rsa_open_string));
            }
            catch (Exception e) {
                Logger.Log(sslStreamRW.GetIpFormated() + "Error in parsing keys from database", 3);
                sslStreamRW.Disconnect("Serverside error\nid = " + sslStreamRW.Id + ")");
                conn.Close();
                return false;
            }
            
            new SecureRandom().NextBytes(generated_bytes);

            byte[] recieved_bytes;
            try
            {
                if (!sslStreamRW.WriteBytes(generated_bytes)) return false;
                if (!sslStreamRW.ReadBytes(out recieved_bytes)) return false;
            }
            catch(Exception e)
            {
                Logger.Log(sslStreamRW.GetIpFormated() + "Error in token exchange. Exception: " + e.Message + "; " + e.InnerException, 3);
                sslStreamRW.Disconnect("Serverside error\nid = " + sslStreamRW.Id + ")");
                return false;
            }

            ISigner signer = SignerUtilities.GetSigner("GOST3411withGOST3410");
            signer.Init(false, gost_cert.GetPublicKey());
            signer.BlockUpdate(generated_bytes, 0, generated_bytes.Length);


            if (signer.VerifySignature(recieved_bytes))
            {
                if (requestPool.ContainsKey(login))
                {
                    requestPool[login] = true;
                }
                else
                {
                    Logger.Log(sslStreamRW.GetIpFormated() + "No active authentication requests");
                    sslStreamRW.Disconnect("No active authentication requests");
                    return false;
                }

                Logger.Log(sslStreamRW.GetIpFormated() + "Authenticated!");
                sslStreamRW.WriteString("<APPROVED>");
                sslStreamRW.Disconnect("Proper auth");
                
            }
            else
            {
                sslStreamRW.WriteString("<WRONG TOKEN>");
                sslStreamRW.Disconnect("Wrong token/decryption");
            }

            
            return true;
        }

        //Server constructor/config
        public Server()
        {
            string filepath = "C:\\Users\\Admin\\Desktop\\Logs\\ServerLog_" + DateTime.Now.ToString().Replace(' ','_').Replace(':','.').Replace('.','_') + ".txt";
            Console.WriteLine(filepath);
            Logger.OpenFile(filepath);
            Logger.LogLevel = 0;
            
            sqlUser = "fingerpassserver";
            sqlPass = "matrixislayered";
            sqlName = "fingerpassserverdb";

            stringBuilder = new NpgsqlConnectionStringBuilder();
            stringBuilder.Host = "127.0.0.1";
            stringBuilder.Port = 5432;
            stringBuilder.Password = sqlPass;
            stringBuilder.Username = sqlUser;
            stringBuilder.Database = sqlName;

            conn = new NpgsqlConnection(stringBuilder.ToString());

            conn.Open();

            new NpgsqlCommand("CREATE TABLE IF NOT EXISTS devices (id SERIAL PRIMARY KEY, device_name NAME NOT NULL, imei TEXT NOT NULL, restore_code INTEGER NOT NULL," +
                                                                  "device_open_key TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES auth_user (id))", conn).ExecuteNonQuery();
            new NpgsqlCommand("GRANT ALL ON devices TO fingerpassserver", conn).ExecuteNonQuery();

            conn.Close();
            alive = true;

            serverCertificate = new X509Certificate2("fingerpass.ru.pfx","metalinmyblood");


            sslOutListener = new TcpListener(IPAddress.Any, 6284);
            sslOutListener.Start();

            frontListener = new TcpListener(IPAddress.Any, 6285);
            frontListener.Start();

            ListenSslConnection.Start();
            ListenFront.Start();

            ListenSslConnection.Wait();
        }
    }
}
