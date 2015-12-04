using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BtmI2p.MiscUtils;
using BtmI2p.ComputableTaskInterfaces.Client;
using BtmI2p.TaskSolvers.Scrypt;
using Xunit;
using Xunit.Abstractions;

namespace TestClientExternalCommunication
{
    public class TestTaskSolvers
    {
        private readonly ITestOutputHelper _output;
        public TestTaskSolvers(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task Test1()
        {
            var taskB64 ="ew0KICAiQ29tbW9uSW5mbyI6IHsNCiAgICAiVGFza0d1aWQiOiAiNjM3MDQ4MjMtY2E3NS00MGU5LTkyMTgtMDAzYmJiZTY1NzIyIiwNCiAgICAiVmFsaWRVbnRpbCI6ICIyMDE1LTA3LTEwVDExOjQ3OjE2IiwNCiAgICAiVGFza1R5cGUiOiAwLA0KICAgICJCYWxhbmNlR2FpbiI6IDENCiAgfSwNCiAgIlRhc2tEZXNjcmlwdGlvbiI6IHsNCiAgICAiUGFzc1NhbHRTaXplIjogMzIsDQogICAgIk4iOiAxNjM4NCwNCiAgICAiUiI6IDgsDQogICAgIlAiOiAxLA0KICAgICJEa0xlbiI6IDIsDQogICAgIlNhbHQiOiAiVlNmbEg0T2VmTlZkRllHWTl0NXdqTGZwSnlNbTdKK0szTFo1SkVDYldidz0iLA0KICAgICJTb2x1dGlvbk1hc2siOiAiLzhBPSIsDQogICAgIlNvbHV0aW9uRXF1YWwiOiAibklNPSINCiAgfQ0KfQ==";
            var solutionB64 = "ew0KICAiQ29tbW9uSW5mbyI6IHsNCiAgICAiVGFza0d1aWQiOiAiNjM3MDQ4MjMtY2E3NS00MGU5LTkyMTgtMDAzYmJiZTY1NzIyIiwNCiAgICAiVmFsaWRVbnRpbCI6ICIyMDE1LTA3LTEwVDExOjQ3OjE2LjM0MTk0NTRaIiwNCiAgICAiVGFza1R5cGUiOiAwLA0KICAgICJCYWxhbmNlR2FpbiI6IDENCiAgfSwNCiAgIlRhc2tTb2x1dGlvbiI6IHsNCiAgICAiU29sdXRpb25QYXNzIjogIkRsMmJOSy9obGxOeDVyamNhOS9lcDBaNzZ2Rk53N0Izd0hGN2w5azNTMlE9Ig0KICB9DQp9";
            var task =
                Encoding.UTF8.GetString(Convert.FromBase64String(taskB64))
                    .ParseJsonToType<ComputableTaskDescription<ScryptTaskDescription>>();
            var soluion =
                Encoding.UTF8.GetString(Convert.FromBase64String(solutionB64))
                    .ParseJsonToType<ComputableTaskSolution<ScryptTaskSolution>>();
            _output.WriteLine(task.WriteObjectToJson());
            _output.WriteLine(soluion.WriteObjectToJson());
            //Assert.True(await ScryptTaskSolver.CheckTaskSolution(task, soluion));
            var passBytes = soluion.TaskSolution.SolutionPass;
            var res = ScryptTaskSolver.ScryptCompute(
                passBytes,
                task.TaskDescription,
                ScryptTaskSolver.EUseNativeScrypt.WinDll
            );
            _output.WriteLine(MiscFuncs.ToBinaryString(res));
            _output.WriteLine(MiscFuncs.ToBinaryString(task.TaskDescription.SolutionMask));
            _output.WriteLine(MiscFuncs.ToBinaryString(task.TaskDescription.SolutionEqual));
        }

        [Fact]
        public void TestNativeManagedScryptEqual(
            ScryptTaskSolver.EUseNativeScrypt native 
                = ScryptTaskSolver.EUseNativeScrypt.WinDll
        )
        {
            const int dkLen = 32;
            var taskDesc = new ScryptTaskDescription()
            {
                N = 32768,
                R = 8,
                P = 1,
                DkLen = dkLen,
                PassSaltSize = 32,
                Salt = new byte[32],
                SolutionMask = new byte[dkLen],
                SolutionEqual = new byte[dkLen]
            };
            var passBytes = new byte[taskDesc.PassSaltSize];
            for (int i = 0; i < 30; i++)
            {
                MiscFuncs.GetRandomBytes(passBytes);
                var r1 = ScryptTaskSolver.ScryptCompute(
                    passBytes, taskDesc, ScryptTaskSolver.EUseNativeScrypt.None
                );
                Assert.Equal(
                    r1,
                    ScryptTaskSolver.ScryptCompute(
                        passBytes, taskDesc, native
                    )
                );
            }
        }

        [Fact]
        public async Task TestComputeTime()
        {
            int cpuCount = Environment.ProcessorCount;
            _output.WriteLine("Cpu count {0}", cpuCount);
            const int dkLen = 32;
            var taskDesc = new ScryptTaskDescription()
            {
                N = 32768,
                R = 8,
                P = 1,
                DkLen = dkLen,
                PassSaltSize = 32,
                Salt = new byte[32],
                SolutionMask = new byte[dkLen],
                SolutionEqual = new byte[dkLen]
            };
            const int tryCount = 100;
            int maxThreads = 4;
            _output.WriteLine("Thread count {0}", maxThreads);
            var lockSem = new SemaphoreSlim(maxThreads);
            var sw = new Stopwatch();
            sw.Start();
            var tasks = new Task<byte[]>[tryCount];
            for (int i = 0; i < tryCount; i++)
            {
                var passBytes = new byte[taskDesc.PassSaltSize];
                MiscFuncs.GetRandomBytes(passBytes);
                tasks[i] = Task.Factory.StartNew(
                    async () =>
                    {
                        using (await lockSem.GetDisposable().ConfigureAwait(false))
                        {
                            _output.WriteLine("{0}", DateTime.Now);
                            return ScryptTaskSolver.ScryptCompute(
                                passBytes, taskDesc,
                                ScryptTaskSolver.EUseNativeScrypt.None
                            );
                        }
                    },
                    TaskCreationOptions.LongRunning
                ).Unwrap();
            }
            await Task.WhenAll(tasks).ConfigureAwait(false);
            var taskRes = tasks.Select(x => x.Result);
            sw.Stop();
            _output.WriteLine(
                "{0}",
                sw.ElapsedMilliseconds/tryCount
            );
        }
        
        [Fact]
        public async Task TestScryptSolver()
        {
            const int dkLen = 1;
            var origTaskDesc = new ScryptTaskDescription()
            {
                N = 32768,
                R = 8,
                P = 1,
                DkLen = dkLen,
                PassSaltSize = 32,
                Salt = new byte[32],
                SolutionMask = new byte[dkLen],
                SolutionEqual = new byte[dkLen]
            };
            const decimal oneBitIncome = 1.0m/32.0m;
            const long wishfulIncome = 1;
            int n = 50;
            var its = new MutableTuple<int,long>[n];
            int threadCount = 4;
            for (int i = 0; i < n; i++)
            {
                var taskDesc = ScryptTaskDescriptionGenerator
                    .GetTaskDescriptionParams(
                        wishfulIncome,
                        DateTime.UtcNow + TimeSpan.FromHours(1.0d),
                        oneBitIncome,
                        origTaskDesc
                    );
                var sw = new Stopwatch();
                sw.Start();
                var debugInfo = new ScryptTaskSolver.SolveScryptTaskDebugInfo();
                var rightResult = await ScryptTaskSolver.SolveScryptTask(
                    taskDesc,
                    CancellationToken.None,
                    threadCount,
                    ScryptTaskSolver.EUseNativeScrypt.WinDll,
                    debugInfo
                ).ConfigureAwait(false);
                sw.Stop();
                its[i] = new MutableTuple<int, long>()
                {
                    Item1 = debugInfo.IterationCount,
                    Item2 = sw.ElapsedMilliseconds
                };
                _output.WriteLine(
                    "Elapsed {0}ms iteration {1} pass {2}",
                    sw.ElapsedMilliseconds,
                    debugInfo.IterationCount,
                    Convert.ToBase64String(rightResult.TaskSolution.SolutionPass)
                );
            }
            _output.WriteLine("Avg its {0}", its.Select(x => x.Item1).Average());
            _output.WriteLine(
                "Avg compute time {0} for {1} threads", 
                its.Select(x => x.Item2).Sum() / its.Select(x => x.Item1).Sum(),
                threadCount
            );
        }
    }
}
