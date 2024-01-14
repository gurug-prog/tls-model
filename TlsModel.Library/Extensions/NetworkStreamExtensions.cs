using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace TlsModel.Library.Extensions;

public static class NetworkStreamExtensions
{
    public static void SendMessage(this NetworkStream stream, byte[] message)
    {
        stream.Write(message, 0, message.Length);
    }

    public static byte[] ReceiveMessage(this NetworkStream stream)
    {
        byte[] buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        byte[] message = new byte[bytesRead];
        Array.Copy(buffer, message, bytesRead);
        return message;
    }
}
