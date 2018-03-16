using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Npgsql;

namespace FingerPassServer
{
    class SqlRW
    {
        public static bool Insert(string table,string columns,string values, NpgsqlConnection connection) {
            try
            {
                new NpgsqlCommand("INSERT INTO " + table + " (" + columns + ") VALUES (" + values + ");", connection).ExecuteNonQuery();
            }
            catch (Exception e){
                Console.WriteLine("Error PostgreSQL INSERT:\n" + e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                return false;
            }
            return true;
        }

        public static bool Select(string values, string table, NpgsqlConnection connection, out NpgsqlDataReader reader) {
            reader = null;
            try
            {
                reader = new NpgsqlCommand("SELECT "+values+" FROM "+table+";", connection).ExecuteReader();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error PostgreSQL INSERT:\n" + e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                return false;
            }
            return true;
        }
    }
}
