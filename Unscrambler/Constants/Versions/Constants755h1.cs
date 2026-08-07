using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For755h1() => new() {
		GameVersion = "2026.08.05.0000.0000",
		TableOffsets = [0x22E1610, 0x22FB100, 0x230A5C0],
		TableSizes = [26299 * 4, 15662 * 4, 20792 * 4],
		TableRadixes = [119, 82, 113],
		TableMax = [221, 191, 184],
		MidTableOffset = 0x22E1170,
		MidTableSize = 148 * 8,
		DayTableOffset = 0x231EAA0,
		DayTableSize = 38 * 4,
		OpcodeKeyTableSize = 89 * 4,
		OpcodeKeyTableOffset = 0x231EB40,
		ObfuscationEnabledMode = 140,
		InitZoneOpcode = 0x28D,
		UnknownObfuscationInitOpcode = 0x128,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0xE9,
		FateInfoLength = 56,
		FateStart = 2370,
		FateEnd = 2357,
		FateProgress = 2364,
		ObfuscatedOpcodes = new Dictionary<string, int> {
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
		}
	};
}