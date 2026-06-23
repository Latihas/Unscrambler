using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For751h2() => new() {
		GameVersion = "2026.06.18.0000.0000",
		TableOffsets = [0x22DCFC0, 0x22E6FB0, 0x22EF590],
		TableSizes = [10234 * 4, 8568 * 4, 15808 * 4],
		TableRadixes = [119, 119, 104],
		TableMax = [86, 72, 152],
		MidTableOffset = 0x22DCC80,
		MidTableSize = 104 * 8,
		DayTableOffset = 0x22FEC90,
		DayTableSize = 49 * 4,
		OpcodeKeyTableSize = 105 * 4,
		OpcodeKeyTableOffset = 0x22FED60,
		ObfuscationEnabledMode = 72,
		InitZoneOpcode = 0x337,
		UnknownObfuscationInitOpcode = 0xD7,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0x22E,
		FateInfoLength = 56,
		FateStart = 2370,
		FateEnd = 2357,
		FateProgress = 2364,
		ObfuscatedOpcodes = new Dictionary<string, int> {
			{ "PlayerSpawn", 0x2E0 },
			{ "NpcSpawn", 0x378 },
			{ "NpcSpawn2", 0x188 },
			{ "ActionEffect01", 0x37D },
			{ "ActionEffect08", 0x350 },
			{ "ActionEffect16", 0x27E },
			{ "ActionEffect24", 0x1A4 },
			{ "ActionEffect32", 0x2A2 },
			{ "StatusEffectList", 0x132 },
			{ "StatusEffectList3", 0x28B },
			{ "Examine", 0x32C },
			{ "UpdateGearset", 0x333 },
			{ "UpdateParty", 0x3DC },
			{ "ActorControl", 0x19F },
			{ "ActorCast", 0x1C9 },
			{ "UnknownEffect01", 0x144 },
			{ "UnknownEffect16", 0x346 },
			{ "ActionEffect02", 0x1DA },
			{ "ActionEffect04", 0x2B8 }
		}
	};
}