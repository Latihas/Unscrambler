namespace Unscrambler.Constants.Versions;

public static partial class GameConstants
{
    [VersionConstant]
    public static VersionConstants For755()
    {
        return new VersionConstants
        {
            GameVersion = "2026.07.16.0001.0000",
            TableOffsets = [0x22E0B00, 0x22E7220, 0x22EBF00],
            TableSizes = [6600 * 4, 4920 * 4, 15327 * 4],
            TableRadixes = [88, 120, 131],
            TableMax = [75, 41, 117],
            MidTableOffset = 0x22E0530,
            MidTableSize = 186 * 8,
            DayTableOffset = 0x22FAE80,
            DayTableSize = 21 * 4,
            OpcodeKeyTableSize = 186 * 4,
            OpcodeKeyTableOffset = 0x22FAEE0,
            ObfuscationEnabledMode = 24,
            InitZoneOpcode = 0x2D9,
            UnknownObfuscationInitOpcode = 0x3DE,
            ObfuscatedOpcodes = new Dictionary<string, int>
            {
                { "PlayerSpawn", 0x71 },
                { "NpcSpawn", 0x80 },
                { "NpcSpawn2", 0x146 },

                { "ActionEffect01", 0x1F3 },
                { "ActionEffect08", 0x114 },
                { "ActionEffect16", 0x2CD },
                { "ActionEffect24", 0xED },
                { "ActionEffect32", 0x2C7 },

                { "StatusEffectList", 0x14C },
                { "StatusEffectList3", 0x2E8 },

                { "Examine", 0x288 },
                { "UpdateGearset", 0x308 },
                { "UpdateParty", 0x17F },
                { "ActorControl", 0x112 },
                { "ActorCast", 0x16B },

                { "UnknownEffect01", 0xDB },
                { "UnknownEffect16", 0x255 },
                { "ActionEffect02", 0x355 },
                { "ActionEffect04", 0x1E5 }
            },
        };
    }
}