using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For756() => new() {
		GameVersion = "2026.09.01.0000.0000",
		TableOffsets = [0x22E8CB0, 0x22FE880, 0x2303230],
		TableSizes = [22260 * 4, 4715 * 4, 10912 * 4],
		TableRadixes = [105, 115, 124],
		TableMax = [212, 41, 88],
		MidTableOffset = 0x22E84F0,
		MidTableSize = 248 * 8,
		DayTableOffset = 0x230DCB0,
		DayTableSize = 21 * 4,
		OpcodeKeyTableSize = 193 * 4,
		OpcodeKeyTableOffset = 0x230DD10,
		ObfuscationEnabledMode = 12,
		InitZoneOpcode = 0x3A1,
		UnknownObfuscationInitOpcode = 0x66,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0x106,
		FateInfoLength = 56,
		FateStart = 2370,
		FateEnd = 2357,
		FateProgress = 2364,
		ObfuscatedOpcodes = new Dictionary<string, int> {
			{ "PlayerSpawn", 0x3B2 },
			{ "NpcSpawn", 0x1C4 },
			{ "NpcSpawn2", 0x26A },
			{ "ActionEffect01", 0x2EC },
			{ "ActionEffect08", 0xFD },
			{ "ActionEffect16", 0x357 },
			{ "ActionEffect24", 0xB4 },
			{ "ActionEffect32", 0x14E },
			{ "StatusEffectList", 0x248 },
			{ "StatusEffectList3", 0x20D },
			{ "Examine", 0x69 },
			{ "UpdateGearset", 0x374 },
			{ "UpdateParty", 0x1DF },
			{ "ActorControl", 0x38C },
			{ "ActorCast", 0x10A },
			{ "UnknownEffect01", 0x1DB },
			{ "UnknownEffect16", 0x34C },
			{ "ActionEffect02", 0x356 },
			{ "ActionEffect04", 0x371 }
		}
	};
}