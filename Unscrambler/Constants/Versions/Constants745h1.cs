namespace Unscrambler.Constants.Versions;

public static class GameConstants {
	public static VersionConstants For745h1() => new() {
		GameVersion = "2026.03.07.0000.0000",
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
				"PlayerSpawn", 0x3CA
			}, {
				"NpcSpawn", 0x3C3
			}, {
				"NpcSpawn2", 0x9F
			}, {
				"ActionEffect01", 0xB6
			}, {
				"ActionEffect08", 0x23E
			}, {
				"ActionEffect16", 0x32C
			}, {
				"ActionEffect24", 0xA2
			}, {
				"ActionEffect32", 0x3D9
			}, {
				"StatusEffectList", 0x1DF
			}, {
				"StatusEffectList3", 0x1B0
			}, {
				"Examine", 0x3C4
			}, {
				"UpdateGearset", 0x1F5
			}, {
				"UpdateParty", 0x328
			}, {
				"ActorControl", 0xE7
			}, {
				"ActorCast", 0x260
			}, {
				"UnknownEffect01", 0x2FE
			}, {
				"UnknownEffect16", 0x3CE
			}, {
				"ActionEffect02", 0x1DA
			}, {
				"ActionEffect04", 0x2BE
			}
		}
	};
}