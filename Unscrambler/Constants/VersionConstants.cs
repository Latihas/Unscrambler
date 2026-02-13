using Unscrambler.Constants.Versions;

namespace Unscrambler.Constants;

public class VersionConstants {
    public string GameVersion { get; init; }

    public byte ObfuscationEnabledMode { get; init; }

    public long[] TableOffsets { get; init; } = [];
    public int[] TableSizes { get; init; } = [];
    public int[] TableRadixes { get; init; } = [];
    public int[] TableMax { get; init; } = [];

    public long MidTableOffset { get; init; }
    public int MidTableSize { get; init; }

    public long DayTableOffset { get; init; }
    public int DayTableSize { get; init; }

    public long OpcodeKeyTableOffset { get; init; }
    public int OpcodeKeyTableSize { get; init; }

    public int InitZoneOpcode { get; init; }
    public int UnknownObfuscationInitOpcode { get; init; }

    public Dictionary<string, int> ObfuscatedOpcodes { get; init; } = [];
    public static Dictionary<string, VersionConstants> Constants { get; } = [];

    static VersionConstants() {
        var _741h1 = GameConstants.For741h1();
        Constants.Add(_741h1.GameVersion, _741h1);
    }

    public static VersionConstants ForGameVersion(string gameVersion) => Constants[gameVersion];
}