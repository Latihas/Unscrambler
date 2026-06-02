using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For75h2() => new() {
		GameVersion = "2026.05.01.0000.0000",
		TableOffsets = [0x22DE5F0, 0x22E6A10, 0x22EDC70],
		TableSizes = [8455 * 4, 7320 * 4, 11220 * 4],
		TableRadixes = [95, 122, 110],
		TableMax = [89, 60, 102],
		MidTableOffset = 0x22DDEA0,
		MidTableSize = 233 * 8,
		DayTableOffset = 0x22F8BC0,
		DayTableSize = 36 * 4,
		OpcodeKeyTableSize = 35 * 4,
		OpcodeKeyTableOffset = 0x22F8C50,
		ObfuscationEnabledMode = 93,
		InitZoneOpcode = 0x237,
		UnknownObfuscationInitOpcode = 0x3C2,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0xE1,
		FateInfoLength = 56,
		FateStart = 56,
		FateEnd = 56,
		FateProgress = 56,
		ObfuscatedOpcodes = new Dictionary<string, int> {
			{ "PlayerSpawn", 0x2AA },
			{ "NpcSpawn", 0xF6 },
			{ "NpcSpawn2", 0xA1 },
			{ "ActionEffect01", 0x1FF },
			{ "ActionEffect08", 0x283 },
			{ "ActionEffect16", 0x309 },
			{ "ActionEffect24", 0x115 },
			{ "ActionEffect32", 0x29A },
			{ "StatusEffectList", 0x65 },
			{ "StatusEffectList3", 0x249 },
			{ "Examine", 0x2C4 },
			{ "UpdateGearset", 0xB6 },
			{ "UpdateParty", 0x371 },
			{ "ActorControl", 0x343 },
			{ "ActorCast", 0x25C },
			{ "UnknownEffect01", 0x3E2 },
			{ "UnknownEffect16", 0x16A },
			{ "ActionEffect02", 0x207 },
			{ "ActionEffect04", 0xA8 }
		}
	};
}