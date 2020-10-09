using FlatSharp;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.AccessControl;
using System.Text;
//using System.Text.Json;
//using System.Text.Json.Serialization;

namespace LibToFuzz
{
    public partial class Downstream
    {

    }

    public partial class FSeed
    {

    }

    public partial class ConfigEntry
    {

    }

    public partial class Upstream
    {

    }
    
    public class FuzzMe
    {
        //private static string FakeUpstream =
        //    "{\"structure\": {\"data\": [{\"tag\": \"moves\",\"type\": \"string\",\"used\": true}]}}";
        public static int ParsedFd(string fdString)
        {
            int ptrd = 0;
            for (int i = 0; i < fdString.Length; i++) {
                ptrd = ptrd * 10 + Int32.Parse(fdString[i].ToString());
            }

            return ptrd;
        }

        private static Int64 Deserialize64(char[] buf)
        {
            Int64 result = 0;
            result |= (long)buf[0];
            result |= (long)buf[1] << 8;
            result |= (long)buf[2] << 16;
            result |= (long)buf[3] << 24;
            result |= (long)buf[4] << 32;
            result |= (long)buf[5] << 40;
            result |= (long)buf[6] << 48;
            result |= (long)buf[7] << 56;
            return result;
        }
        private static long Serialize56(char[] buf, Int64 v)
        {
            buf[0] = (char) (v & 0xFF);
            buf[1] = (char) ((v >> 8) & 0xFF);
            buf[2] = (char) ((v >> 16) & 0xFF);
            buf[3] = (char) ((v >> 24) & 0xFF);
            buf[4] = (char) ((v >> 32) & 0xFF);
            buf[5] = (char) ((v >> 40) & 0xFF);
            buf[6] = (char) ((v >> 48) & 0xFF);
            buf[7] = (char)0;
            buf[7] ^= buf[0];
            buf[7] ^= buf[1];
            buf[7] ^= buf[2];
            buf[7] ^= buf[3];
            buf[7] ^= buf[4];
            buf[7] ^= buf[5];
            buf[7] ^= buf[6];
            return buf[7];
        }
        
        static void Main(string[] args)
        {
            Upstream up = new Upstream();
            up.Structure = new FSeed();
            up.Structure.Data = new ConfigEntry[1];
            var e0 = new ConfigEntry();
            up.Structure.Data[0] = e0;
            e0.Tag = "stuff";
            e0.Type = "string";
            e0.Used = true;
            
            Console.WriteLine("test serializing up");
            
            var testBuffer = new byte[1000];
            
            var serializer = new FlatBufferSerializer(new FlatBufferSerializerOptions(FlatBufferDeserializationOption.Default));
            
            var testLength = serializer.Serialize(up, testBuffer);
            
            Upstream up2 = serializer.Parse<Upstream>(testBuffer);
            
            
            Console.WriteLine("Starting Main");
            
            // For some reason, I have to copy the args into a local array, or else they disappear
            int[] fileDescriptors = new int[2];
            for (int i = 0; i < fileDescriptors.Length && i < args.Length; i++)
            {
                int n = ParsedFd(args[i]);
                Console.WriteLine(n);
                fileDescriptors[i] = n;
            }
            
            // Grab the FDs from the environment variables and translate to a IntPtr
            int fdNumIn = fileDescriptors[0];
            SafeFileHandle inPipeHandle = new SafeFileHandle(new IntPtr(fdNumIn), true);
            
            int fdNumOut = fileDescriptors[1];
            SafeFileHandle outPipeHandle = new SafeFileHandle(new IntPtr(fdNumOut), true);

            Console.WriteLine("GO_FUZZ_IN_FD: " + fdNumIn);
            Console.WriteLine("GO_FUZZ_OUT_FD: " + fdNumOut);

            string[] commName = new string[4];
            for (int i = 2; i < args.Length; i++)
            {
                commName[i-2] = args[i];
                Console.WriteLine(("comm" + (i - 2)) + ": " + commName[(i - 2)]);
            }

            const int MaxInputSize = 1 << 24;
            const int ReturnResultSize = 1 << 25;
            const int CoverSize = 64 << 10;
            const int SonarRegionSize = 1 << 20;
            
            // Use the filehandles
            Stream inStream = new FileStream(inPipeHandle, FileAccess.Read);
            Console.WriteLine("created inStream");
            Stream outStream = new FileStream(outPipeHandle, FileAccess.Write);
            Console.WriteLine("created outStream");
            
            MemoryMappedFileSecurity security = new MemoryMappedFileSecurity();
            security.AddAccessRule(new AccessRule<MemoryMappedFileRights>(("Everyone"), MemoryMappedFileRights.FullControl, AccessControlType.Allow));
 
            Console.WriteLine("created security");
            
            MemoryMappedFile comm0 = MemoryMappedFile.OpenExisting(commName[0], MemoryMappedFileRights.ReadWrite, HandleInheritability.Inheritable);
            Console.WriteLine("created comm0");
            var comm0Accessor = comm0.CreateViewAccessor(0, MaxInputSize);
            Console.WriteLine("created comm0Accessor");
            
            MemoryMappedFile comm1 = MemoryMappedFile.OpenExisting(commName[1], MemoryMappedFileRights.ReadWrite, HandleInheritability.Inheritable);
            Console.WriteLine("created comm1");
            var comm1Accessor = comm1.CreateViewAccessor(0, ReturnResultSize);
            Console.WriteLine("created comm1Accessor");
            
            MemoryMappedFile comm2 = MemoryMappedFile.OpenExisting(commName[2], MemoryMappedFileRights.ReadWrite, HandleInheritability.Inheritable);
            Console.WriteLine("created comm2");
            var comm2Accessor = comm2.CreateViewAccessor(0, CoverSize);
            Console.WriteLine("created comm2Accessor");
            
            //var comm3Stream = new FileStream(commNames[3], FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            //Console.WriteLine("created comm3Stream");
            MemoryMappedFile comm3 = MemoryMappedFile.OpenExisting(commName[3], MemoryMappedFileRights.ReadWrite, HandleInheritability.Inheritable);
            Console.WriteLine("created comm3");
            var comm3Accessor = comm3.CreateViewAccessor(0, SonarRegionSize);
            Console.WriteLine("created comm3Accessor");
            
            char[] inPipeBuffer = new char[10];
            char[] outputBuffer = new char[24];
            char[] returnLengthBuffer = new char[8];
            
            StreamReader inPipeReader = new StreamReader(inStream);
            StreamWriter outputWriter = new StreamWriter(outStream);
            
            while (true)
            {
                inPipeReader.Read(inPipeBuffer, 0, inPipeBuffer.Length);

                int fnidx = inPipeBuffer[0];
                fnidx += inPipeBuffer[1] << 8;
                Console.WriteLine("fnidx: " + fnidx);

                char[] lengthBuffer = new char[8];
                for (int i = 2; i < inPipeBuffer.Length; i++)
                {
                    lengthBuffer[i-2] = inPipeBuffer[i];
                }
                Int64 inputLength = Deserialize64(lengthBuffer);
                Console.WriteLine("input length: " + inputLength);

                // read inputBuffer data from comm0
                var inputBuffer = new byte[inputLength];
                comm0Accessor.ReadArray(0, inputBuffer, 0, (int)inputLength);
                for (int i = 0; i < inputLength; i++)
                {
                    inputBuffer[i] = comm0Accessor.ReadByte(i);
                }

                var inputString = Encoding.UTF8.GetString(inputBuffer);

                Console.WriteLine("downstream: ");
                Console.WriteLine(inputString);
                
                //var downstream = Downstream.Deserialize(inputString);
                var downstream = FlatBufferSerializer.Default.Parse<Downstream>(inputBuffer);
                Console.WriteLine("downstream deserialized");

                var seed = downstream.Seed;
                var entries = seed.Data;
                ConfigEntry entry = null;
                if (entries.Count >= 1)
                {
                    entry = entries[0];
                }
                else
                {
                    Console.WriteLine("zero entries!");
                }

                var value = entry.Value;
                Console.WriteLine("got entry value: " + value);
                
                Int64 res = 0;
                Int64 ns ;
                Int64 sonar = 0;
                Int64 returnLength = 0;
                
                // Start the clock
                var nsStart = DateTime.UtcNow.Ticks;
                
                // Actually run the function to fuzz
                Console.WriteLine("BrokenMethod()");
                Console.WriteLine(BrokenMethod(value));

                ns = DateTime.UtcNow.Ticks - nsStart;
                Console.WriteLine("ns: " + ns);
                
                char[] resBuffer = new char[8];
                char[] nsBuffer = new char[8];
                char[] sonarBuffer = new char[8];

                Serialize56(resBuffer, res);
                Serialize56(nsBuffer, ns);
                Serialize56(sonarBuffer, sonar);

                Console.WriteLine("instantiating upstream");
                
                Upstream upstream = new Upstream();
                upstream.Structure = new FSeed();
                upstream.Structure.Data = new ConfigEntry[1];
                var upEntry = upstream.Structure.Data[0];
                upEntry.Tag = "stuff";
                upEntry.Type = "string";
                upEntry.Used = true;
                
                Console.WriteLine("serializing upstream");
                
                int maxReturnSize = FlatBufferSerializer.Default.GetMaxSize(upstream);
                var returnBuffer = new byte[maxReturnSize];
                returnLength = FlatBufferSerializer.Default.Serialize(upstream, returnBuffer);
                Console.WriteLine("return length: " + returnLength);
                Serialize56(returnLengthBuffer, returnLength);

                for (int i = 0; i < 8; i++)
                {
                    Console.WriteLine("returnLengthBuffer: " + (byte)returnLengthBuffer[i]);
                    comm1Accessor.Write(i, returnLengthBuffer[i]);
                }

                for (int i = 0; i < returnLength; i++)
                {
                    comm1Accessor.Write(i+8, returnBuffer[i]);
                }
                
                comm1Accessor.Flush();
                Console.WriteLine("wrote to comm1Accessor");
                
                for (int i = 0; i < 8; i++)
                {
                    outputBuffer[i] = resBuffer[i];
                    outputBuffer[i+8] = nsBuffer[i];
                    outputBuffer[i+16] = sonarBuffer[i];
                }
                
                outputWriter.Write(outputBuffer, 0, outputBuffer.Length);
                outputWriter.Flush();
                Console.WriteLine("wrote outputbuffer");
            }
        }

        public static int BrokenMethod(string Data)
        {
            int[] ints = new int[5]{0, 1, 2, 3, 4};
            int idx = 0;
            if (Data.Length > 5)
            {
                idx++;
            }
            if (Data.Contains("foo"))
            {
                idx++;
            }
            if (Data.Contains("bar"))
            {
                idx++;
            }
            if (Data.Contains("ouch"))
            {
                idx++;
            }
            if (Data.Contains("omg"))
            {
                idx++;
            }
            return ints[idx];
        }
    }
}
