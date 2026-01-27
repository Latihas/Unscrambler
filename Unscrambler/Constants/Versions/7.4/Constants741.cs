namespace Unscrambler.Constants.Versions;

public static class GameConstants {
    public static VersionConstants For74h2() =>
        new() {
            GameVersion = "2026.01.21.0000.0000",
            TableOffsets = [0x21EC830, 0x21F3160, 0x2200750], 
            TableSizes = [16424 * 4, 13692 * 4, 29700 * 4],//[0]?
            TableRadixes = [0x66, 0x51, 0x87],
            TableMax = [0x42, 0xA9, 0xDC],
            MidTableOffset = 0x21EC290,
            MidTableSize = 224 * 8,//?
            DayTableOffset = 0x221D760,
            DayTableSize = 32 * 4,
            OpcodeKeyTableSize = 108 * 4,//?
            OpcodeKeyTableOffset = 0x221D7E0,
            ObfuscationEnabledMode = 0xF9,
            InitZoneOpcode = 420,
            UnknownObfuscationInitOpcode = 0x88,
            ObfuscatedOpcodes = new Dictionary<string, int> {
                {
                    "PlayerSpawn", 318
                }, {
                    "NpcSpawn", 744
                }, {
                    "NpcSpawn2", 530
                }, {
                    "ActionEffect01", 0x1E7
                }, {
                    "ActionEffect08", 0x77
                }, {
                    "ActionEffect16", 0x38F
                }, {
                    "ActionEffect24", 0xB2
                }, {
                    "ActionEffect32", 0x7C
                }, {
                    "StatusEffectList", 0x31E
                }, {
                    "StatusEffectList3", 0xEB
                }, {
                    "Examine", 565
                }, {
                    "UpdateGearset", 145//ModelEquip
                }, {
                    "UpdateParty", 442
                }, {
                    "ActorControl", 712
                }, {
                    "ActorCast", 417
                }, {
                    "UnknownEffect01", 198//?
                }, {
                    "UnknownEffect16", 577//?
                }, {
                    "ActionEffect02", 251//StatusEffectListForay3
                }, {
                    "ActionEffect04", 997//?
                }
            }
        };
}