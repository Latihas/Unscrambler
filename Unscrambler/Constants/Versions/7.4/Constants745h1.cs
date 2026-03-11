namespace Unscrambler.Constants.Versions;

public static class GameConstants {
    public static VersionConstants For745h1() =>
        new() {
            GameVersion = "2026.02.20.0000.0000",
            TableOffsets = [0x21F0480, 0x21FBE20, 0x220E0A0],
            TableSizes = [11880 * 4, 18592 * 4, 19504 * 4],
            TableRadixes = [107, 110, 106],
            TableMax = [111, 169, 184],
            MidTableOffset = 0x21EFE30,
            MidTableSize = 201 * 8,
            DayTableOffset = 0x2221160,
            DayTableSize = 45 * 4,
            OpcodeKeyTableSize = 46 * 4,
            OpcodeKeyTableOffset = 0x2221220,
            ObfuscationEnabledMode = 47,
            InitZoneOpcode = 0x9D,
            UnknownObfuscationInitOpcode = 0xED,
            ObfuscatedOpcodes = new Dictionary<string, int> {
                {
                    "PlayerSpawn", 0x1A4
                }, {
                    "NpcSpawn", 0x304
                }, {
                    "NpcSpawn2", 0x379
                }, {
                    "ActionEffect01", 0x2FA
                }, {
                    "ActionEffect08", 0x3BE
                }, {
                    "ActionEffect16", 0x228
                }, {
                    "ActionEffect24", 0x26F
                }, {
                    "ActionEffect32", 0x210
                }, {
                    "StatusEffectList", 0x6F
                }, {
                    "StatusEffectList3", 0x330
                }, {
                    "Examine", 0x8B
                }, {
                    "UpdateGearset", 569
                }, {
                    "UpdateParty", 0x2A1
                }, {
                    "ActorControl", 0x114
                }, {
                    "ActorCast", 0x3E0
                }, {
                    "UnknownEffect01", 0x3D6
                }, {
                    "UnknownEffect16", 0x2CB
                }, {
                    "ActionEffect02", 0xD0
                }, {
                    "ActionEffect04", 0x13A
                }
            }
        };
}