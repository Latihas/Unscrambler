namespace Unscrambler.Constants.Versions;

public static partial class GameConstants
{
    [VersionConstant]
    public static VersionConstants For755h1()
    {
        return new VersionConstants
        {
            GameVersion = "2026.08.05.0000.0000",
            TableOffsets = [0x22E5EF0, 0x22FF9E0, 0x230EEA0],
            TableSizes = [26299 * 4, 15662 * 4, 20792 * 4],
            TableRadixes = [119, 82, 113],
            TableMax = [221, 191, 184],
            MidTableOffset = 0x22E5A50,
            MidTableSize = 148 * 8,
            DayTableOffset = 0x2323380,
            DayTableSize = 38 * 4,
            OpcodeKeyTableSize = 89 * 4,
            OpcodeKeyTableOffset = 0x2323420,
            ObfuscationEnabledMode = 140,
            InitZoneOpcode = 0x28D,
            UnknownObfuscationInitOpcode = 0x128,
            ObfuscatedOpcodes = new Dictionary<string, int>
            {
                { "PlayerSpawn", 0x398 },
                { "NpcSpawn", 0x6F },
                { "NpcSpawn2", 0x287 },

                { "ActionEffect01", 0x296 },
                { "ActionEffect08", 0x164 },
                { "ActionEffect16", 0x1B1 },
                { "ActionEffect24", 0x39B },
                { "ActionEffect32", 0x372 },

                { "StatusEffectList", 0x1F1 },
                { "StatusEffectList3", 0x153 },

                { "Examine", 0x2BB },
                { "UpdateGearset", 0x336 },
                { "UpdateParty", 0x1B8 },
                { "ActorControl", 0x1DA },
                { "ActorCast", 0x18C },

                { "UnknownEffect01", 0xBF },
                { "UnknownEffect16", 0x115 },
                { "ActionEffect02", 0x305 },
                { "ActionEffect04", 0x14D }
            },
        };
    }
}