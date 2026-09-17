using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For756() => new() {
		GameVersion = "2026.09.15.0000.0000",
		TableOffsets = [0x22E8EF0, 0x22F3200, 0x2302250],
		TableSizes = [10434 * 4, 15379 * 4, 14175 * 4],
		TableRadixes = [94, 91, 105],
		TableMax = [111, 169, 135],
		MidTableOffset = 0x22E8790,
		MidTableSize = 236 * 8,
		DayTableOffset = 0x230FFD0,
		DayTableSize = 44 * 4,
		OpcodeKeyTableSize = 165 * 4,
		OpcodeKeyTableOffset = 0x2310080,
		ObfuscationEnabledMode = 176,
		InitZoneOpcode = 0x32B,
		UnknownObfuscationInitOpcode = 0x2A4,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0x154,
		FateInfoLength = 56,
		FateStart = 2370,
		FateEnd = 2357,
		FateProgress = 2364,
		ObfuscatedOpcodes = new Dictionary<string, int> {
			{ "PlayerSpawn", 0x1C4 },
			{ "NpcSpawn", 0x20C },
			{ "NpcSpawn2", 0x1BD },
			{ "ActionEffect01", 0x313 },
			{ "ActionEffect08", 0x21C },
			{ "ActionEffect16", 0x8C },
			{ "ActionEffect24", 0x30A },
			{ "ActionEffect32", 0x3AA },
			{ "StatusEffectList", 0x83 },
			{ "StatusEffectList3", 0x3DC },
			{ "Examine", 0x1F2 },
			{ "UpdateGearset", 0x10F },
			{ "UpdateParty", 0x191 },
			{ "ActorControl", 0x25F },
			{ "ActorCast", 0x162 },
			{ "UnknownEffect01", 0x3BD },
			{ "UnknownEffect16", 0x27D },
			{ "ActionEffect02", 0x30B },
			{ "ActionEffect04", 0x292 }
		}
	};
}