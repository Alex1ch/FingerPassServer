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

namespace FingerPassServer
{
    class Server
    {
        static X509Certificate2 serverCertificate = null;
        static TcpListener listener;
        static bool alive;
        string sqlUser = "fingerpassserver";
        string sqlPass = "matrixislayered";
        string sqlName = "fingerpassserverdb";
        static NpgsqlConnectionStringBuilder stringBuilder;
        Dictionary<IPAddress, SslStream> sslStreamDict = new Dictionary<IPAddress, SslStream>();

        static NpgsqlConnection conn;

        static List<Task> tasks = new List<Task>();

        public static bool Alive { get => alive; set => alive = value; }

        static string CleanUpTasks() {
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


        Task ListenTcpConnection = new Task(() => {
        Console.WriteLine("Server is up, waiting for connections");

        while (alive) {
            TcpClient client = listener.AcceptTcpClient();
                
            Console.WriteLine(CleanUpTasks());

                Task ClientHandler = new Task(() => {

                    try
                    {
                        SslStreamRW sslStreamRW = new SslStreamRW(client, serverCertificate);

                        Console.WriteLine("TCP Client connected - "+sslStreamRW.Ip+ " -  id: " + sslStreamRW.Id);

                        string message;

                        while (sslStreamRW.Alive&&alive)
                        {
                            if (sslStreamRW.ReadString(out message))
                            {
                                if(message.Length!=0)
                                    Console.WriteLine("Recieved message: " + message);
                                if (message == "<HANDSHAKE>") {
                                    Handshake(sslStreamRW);
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
                        Console.WriteLine("Exception: {0}", e.Message);
                        if (e.InnerException != null)
                        {
                            Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                        }
                        return;
                    }
                });

                ClientHandler.Start();
                tasks.Add(ClientHandler);

            }
        });


        static bool Handshake(SslStreamRW sslStreamRw) {

            string login, pass_hash, device_rsa_open_key, server_rsa_private_key, server_rsa_open_key, device_name;
            if (!sslStreamRw.ReadString(out login)) return false;
            if (!sslStreamRw.ReadString(out device_name)) return false;

            string salt, rounds, hash, user_id;
            login = login.Replace("'", "");

            var connection = new NpgsqlConnection(stringBuilder.ToString());

            connection.Open();

            try
            {
                string[] splits;
                splits = new NpgsqlCommand("SELECT password FROM auth_user WHERE username = '" + login + "'", connection).ExecuteScalar().ToString().Split('$');
                user_id = new NpgsqlCommand("SELECT id FROM auth_user WHERE username = '" + login + "'", connection).ExecuteScalar().ToString();
                hash = splits[3];
                salt = splits[2];
                rounds = splits[1];
            }
            catch (Exception e)
            {
                Console.WriteLine("Error in sql request:\n" + e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                if (e.Message == "Object reference not set to an instance of an object.")
                {
                    sslStreamRw.Disconnect("User wasn't found");
                    connection.Close();
                    return false;
                }
                connection.Close(); 
                sslStreamRw.Disconnect();
                return false;
            }

            if (!sslStreamRw.WriteString(salt)) return false;
            if (!sslStreamRw.WriteString(rounds)) return false;
            if (!sslStreamRw.ReadString(out pass_hash)) return false;

            if (pass_hash != hash)
            {
                sslStreamRw.Disconnect("Wrong password");
                return false;
            }

            var rsa = new RSACryptoServiceProvider(2048);
            server_rsa_private_key = rsa.ToXmlString(true);
            server_rsa_open_key = rsa.ToXmlString(false);

            if (!sslStreamRw.WriteString(server_rsa_open_key)) return false;
            if (!sslStreamRw.ReadString(out device_rsa_open_key)) return false;

            Console.WriteLine("Device Name: {3}\nDB Hash: {0}\nRecieved hash: {1}\nRecieved device open key: {2}", hash, pass_hash, device_rsa_open_key, device_name);
            try
            {
                new NpgsqlCommand(String.Format("INSERT INTO devices (device_name,serv_private_key,serv_open_key,device_open_key,user_id) " +
                    "values ('{0}','{1}','{2}','{3}','{4}');", device_name, server_rsa_private_key, server_rsa_open_key, device_rsa_open_key, user_id), connection).ExecuteNonQuery();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error in sql insert:\n" + e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                sslStreamRw.Disconnect("Something goes wrong in adding device");
                return false;
            }
            finally {
                connection.Close();
            }
            Console.WriteLine("Handshake successful");
            //if (!sslStreamRw.ReadString(out device_rsa_open_key)) return false;
            if (!sslStreamRw.WriteString("<ACCEPTED>")) return false;
            return true;
        }


        public Server()
        {
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

            new NpgsqlCommand("CREATE TABLE IF NOT EXISTS devices (id SERIAL PRIMARY KEY, device_name NAME NOT NULL," +
                                                                  "serv_private_key TEXT NOT NULL, serv_open_key TEXT NOT NULL," +
                                                                  "device_open_key TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES auth_user (id))", conn).ExecuteNonQuery();
            new NpgsqlCommand("GRANT ALL ON devices TO fingerpassserver", conn).ExecuteNonQuery();

            conn.Close();
            alive = true;

            serverCertificate = new X509Certificate2("fingerpass.ru.pfx","metalinmyblood");
     

            listener = new TcpListener(IPAddress.Any, 6284);
            listener.Start();


            ListenTcpConnection.Start();
            ListenTcpConnection.Wait();
        }
    }
}
