using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For755() => new() {
		GameVersion = "2026.07.16.0001.0000",
		TableOffsets = [0x22DF110, 0x22E5830, 0x22EA510],
		TableSizes = [6600 * 4, 4920 * 4, 15327 * 4],
		TableRadixes = [88, 120, 131],
		TableMax = [75, 41, 117],
		MidTableOffset = 0x22DEB40,
		MidTableSize = 186 * 8,
		DayTableOffset = 0x22F9490,
		DayTableSize = 21 * 4,
		OpcodeKeyTableSize = 186 * 4,
		OpcodeKeyTableOffset = 0x22F94F0,
		ObfuscationEnabledMode = 24,
		InitZoneOpcode = 0x2D9,
		UnknownObfuscationInitOpcode = 0x3DE,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0xA6,
		FateInfoLength = 56,
		FateStart = 2370,
		FateEnd = 2357,
		FateProgress = 2364,
		ObfuscatedOpcodes = new Dictionary<string, int> {
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
		}
	};
}