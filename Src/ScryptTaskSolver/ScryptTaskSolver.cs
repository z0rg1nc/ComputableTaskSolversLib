using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using BtmI2p.ComputableTaskInterfaces.Client;
using BtmI2p.CryptSharp.Utility;
using BtmI2p.MiscUtils;
using NLog;

namespace BtmI2p.TaskSolvers.Scrypt
{
    public static class ScryptTaskSolver
    {
        private static void LoadResourceToCurrentFolder(
            string fileName
        )
        {
            var assembly = Assembly.GetExecutingAssembly();
            // EndsWith - because of ILRepack
            if (!assembly.GetManifestResourceNames().Any(x => x.EndsWith(fileName)))
                throw new Exception("Resource not found");
            var resourceName = assembly.GetManifestResourceNames().First(
                x => x.EndsWith(fileName)
            );
            using (var resource = assembly.GetManifestResourceStream(resourceName))
            {
                if (resource == null)
                    throw new NullReferenceException("resource");
                using (var fs = new FileStream(Path.Combine(".", fileName), FileMode.Create))
                {
                    const int bufSize = 4096;
                    var buffer = new byte[bufSize];
                    int readBytes;
                    while ((readBytes = resource.Read(buffer, 0, bufSize)) > 0)
                    {
                        fs.Write(buffer, 0, readBytes);
                    }
                }
            }
        }

        static ScryptTaskSolver()
        {
            try
            {
                var soFileName = IntPtr.Size == 8 
                    ? "libscrypt_x64.so" 
                    : "libscrypt_x86.so";
                LoadResourceToCurrentFolder(
                    soFileName
                );
                var dllFileName = IntPtr.Size == 8
                    ? "ScryptNativeWinDllx64.dll"
                    : "ScryptNativeWinDllx86.dll";
                LoadResourceToCurrentFolder(
                    dllFileName
                );
            }
            catch (Exception exc)
            {
                _log.Error(
                    "ScryptTaskSolver ctor unexpected error '{0}'",
                    exc.ToString()
                );
            }
        }

        private static bool CheckScryptOutput(
            byte[] res,
            byte[] mask,
            byte[] rightSolutionBytes
            )
        {
            if(res == null || mask == null || rightSolutionBytes == null)
                throw new ArgumentNullException();
            if(res.Length == 0)
                throw new ArgumentOutOfRangeException();
            int n = res.Length;
            if(n != mask.Length || n != rightSolutionBytes.Length)
                throw new ArgumentException();
            for (int i = 0; i < n; i++)
            {
                if ((res[i] & mask[i]) != (rightSolutionBytes[i] & mask[i]))
                    return false;
            }
            return true;
        }

        public enum EUseNativeScrypt
        {
            None,
            WinDll,
            LinuxSo
        }

        [DllImport(
            "libscrypt_x86.so",
            EntryPoint = "libscrypt_scrypt",
            CallingConvention = CallingConvention.Cdecl
        )]
        private static extern int LibscryptScrypt86(
            byte[] passwd,
            uint passwdlen,
            byte[] salt,
            uint saltlen,
            ulong n,
            uint r,
            uint p,
            byte[] buf,
            uint buflen
            );

        [DllImport(
            "libscrypt_x64.so",
            EntryPoint = "libscrypt_scrypt",
            CallingConvention = CallingConvention.Cdecl
        )]
        private static extern long LibscryptScrypt64(
            byte[] passwd,
            ulong passwdlen,
            byte[] salt,
            ulong saltlen,
            ulong n,
            uint r,
            uint p,
            byte[] buf,
            ulong buflen
            );

        private static byte[] LinuxNativeComputeScrypt(
            byte[] passBytes,
            ScryptTaskDescription taskDescription
            )
        {
            var result = new byte[taskDescription.DkLen];
            if (IntPtr.Size == 8)
            {
                if (LibscryptScrypt64(
                    passBytes,
                    (ulong)passBytes.Length,
                    taskDescription.Salt,
                    (ulong)taskDescription.Salt.Length,
                    (ulong)taskDescription.N,
                    (uint)taskDescription.R,
                    (uint)taskDescription.P,
                    result,
                    (ulong)taskDescription.DkLen
                    ) != 0
                    )
                {
                    throw new Exception("Some LibscryptScrypt64 internal error");
                }
            }
            else
            {
                if (LibscryptScrypt86(
                    passBytes,
                    (uint)passBytes.Length,
                    taskDescription.Salt,
                    (uint)taskDescription.Salt.Length,
                    (ulong)taskDescription.N,
                    (uint)taskDescription.R,
                    (uint)taskDescription.P,
                    result,
                    (uint)taskDescription.DkLen
                    ) != 0
                    )
                {
                    throw new Exception("Some LibscryptScrypt86 internal error");
                }
            }
            return result;
        }

        [DllImport(
            "ScryptNativeWinDllx86.dll",
            EntryPoint = "crypto_scrypt",
            CallingConvention = CallingConvention.Cdecl
        )]
        private static extern int WindowsScrypt86(
            byte[] passwd,
            uint passwdlen,
            byte[] salt,
            uint saltlen,
            ulong n,
            uint r,
            uint p,
            byte[] buf,
            uint buflen
            );

        [DllImport(
            "ScryptNativeWinDllx64.dll",
            EntryPoint = "crypto_scrypt",
            CallingConvention = CallingConvention.Cdecl
        )]
        private static extern long WindowsScrypt64(
            byte[] passwd,
            ulong passwdlen,
            byte[] salt,
            ulong saltlen,
            ulong n,
            uint r,
            uint p,
            byte[] buf,
            ulong buflen
            );
        private static byte[] WindowsNativeComputeScrypt(
            byte[] passBytes,
            ScryptTaskDescription taskDescription
        )
        {
            var result = new byte[taskDescription.DkLen];
            if (IntPtr.Size == 8)
            {
                if (WindowsScrypt64(
                    passBytes,
                    (ulong)passBytes.Length,
                    taskDescription.Salt,
                    (ulong)taskDescription.Salt.Length,
                    (ulong)taskDescription.N,
                    (uint)taskDescription.R,
                    (uint)taskDescription.P,
                    result,
                    (ulong)taskDescription.DkLen
                    ) != 0
                    )
                {
                    throw new Exception("Some LibscryptScrypt64 internal error");
                }
            }
            else
            {
                if (WindowsScrypt86(
                    passBytes,
                    (uint)passBytes.Length,
                    taskDescription.Salt,
                    (uint)taskDescription.Salt.Length,
                    (ulong)taskDescription.N,
                    (uint)taskDescription.R,
                    (uint)taskDescription.P,
                    result,
                    (uint)taskDescription.DkLen
                    ) != 0
                    )
                {
                    throw new Exception("Some LibscryptScrypt86 internal error");
                }
            }
            return result;
        }

        public static byte[] ScryptCompute(
            byte[] passBytes, 
            ScryptTaskDescription taskDescription, 
            EUseNativeScrypt nativeSupport = EUseNativeScrypt.None
        )
        {
            if (nativeSupport == EUseNativeScrypt.None)
            {
                return SCrypt.ComputeDerivedKey(
                    passBytes,
                    taskDescription.Salt,
                    taskDescription.N,
                    taskDescription.R,
                    taskDescription.P,
                    1,
                    taskDescription.DkLen
                );
            }
            if (nativeSupport == EUseNativeScrypt.WinDll)
            {
                return WindowsNativeComputeScrypt(
                    passBytes,
                    taskDescription
                );
            }
            if (nativeSupport == EUseNativeScrypt.LinuxSo)
            {
                return LinuxNativeComputeScrypt(
                    passBytes,
                    taskDescription
                );
            }
            throw new ArgumentOutOfRangeException(
                "nativeSupport"
            );
        }

        public class SolveScryptTaskDebugInfo
        {
            public int IterationCount = 0;
        }
        public static async Task<ComputableTaskSolution<ScryptTaskSolution>> SolveScryptTask(
            ComputableTaskDescription<ScryptTaskDescription> taskDescription,
            CancellationToken cancellationToken,
            int maxThreads = 1,
            EUseNativeScrypt nativeSupport = EUseNativeScrypt.None,
            SolveScryptTaskDebugInfo debugInfo = null
        )
        {
            var lockSem = new SemaphoreSlim(maxThreads);
            var resultTask = new TaskCompletionSource<ComputableTaskSolution<ScryptTaskSolution>>();
            var tasks = new Task[maxThreads];
            for (int i = 0; i < maxThreads; i++)
            {
                tasks[i] = Task.Run(
                    () =>
                    {
                        var passBytes = new byte
                            [taskDescription.TaskDescription.PassSaltSize];
                        while (
                            !cancellationToken.IsCancellationRequested 
                            && !resultTask.Task.IsCompleted
                            && taskDescription.CommonInfo.ValidUntil > DateTime.UtcNow
                        )
                        {
                            MiscFuncs.GetRandomBytes(passBytes);
                            var res = ScryptCompute(
                                passBytes,
                                taskDescription.TaskDescription,
                                nativeSupport
                            );
                            if (debugInfo != null)
                                Interlocked.Increment(ref debugInfo.IterationCount);
                            if (
                                CheckScryptOutput(
                                    res,
                                    taskDescription.TaskDescription.SolutionMask,
                                    taskDescription.TaskDescription.SolutionEqual
                                )
                            )
                            {
                                var result = new ComputableTaskSolution<ScryptTaskSolution>()
                                {
                                    CommonInfo = taskDescription.CommonInfo,
                                    TaskSolution = new ScryptTaskSolution()
                                    {
                                        SolutionPass = passBytes
                                    }
                                };
                                resultTask.TrySetResult(
                                    result
                                );
                                return;
                            }
                        }
                        resultTask.TrySetCanceled();
                    }
                );
            }
            return await resultTask.Task.ConfigureAwait(false);
        }

        private static readonly Logger _log
            = LogManager.GetCurrentClassLogger();
        public async static Task<bool> CheckTaskSolution(
            ComputableTaskDescription<ScryptTaskDescription> taskDescription,
            ComputableTaskSolution<ScryptTaskSolution> taskSolution
        )
        {
            if(taskDescription == null || taskSolution == null)
                throw new ArgumentNullException();
            if (taskDescription.CommonInfo.TaskGuid != taskSolution.CommonInfo.TaskGuid)
                throw new ArgumentOutOfRangeException(
                    "taskDescription.TaskGuid != taskSolution.TaskGuid"
                );
            var passBytes = taskSolution.TaskSolution.SolutionPass;
            var res = await Task.Factory.StartNew(
                () => ScryptCompute(
                    passBytes, 
                    taskDescription.TaskDescription
                ), 
                TaskCreationOptions.LongRunning
            ).ConfigureAwait(false);
            var result = CheckScryptOutput(
                res, 
                taskDescription.TaskDescription.SolutionMask,
                taskDescription.TaskDescription.SolutionEqual
            );
            return result;
        }
    }
}
