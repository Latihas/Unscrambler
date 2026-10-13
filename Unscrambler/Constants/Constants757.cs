using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants ForNew() => new() {
		GameVersion = "2026.10.06.0000.0000",
		TableOffsets = [0x22EAC20, 0x22FD220, 0x23020F0],
		TableSizes = [18816 * 4, 5043 * 4, 21816 * 4],
		TableRadixes = [84, 123, 108],
		TableMax = [224, 41, 202],
		MidTableOffset = 0x22EA950,
		MidTableSize = 89 * 8,
		DayTableOffset = 0x23175D0,
		DayTableSize = 15 * 4,
		OpcodeKeyTableSize = 83 * 4,
		OpcodeKeyTableOffset = 0x2317610,
		ObfuscationEnabledMode = 254,
		InitZoneOpcode = 0x2CC,
		UnknownObfuscationInitOpcode = 0x2FE,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0x259,
		FateInfoLength = 56,
		FateStart = 2370,
		FateEnd = 2357,
		FateProgress = 2364,
		ObfuscatedOpcodes = new Dictionary<string, int> {
			{ "PlayerSpawn", 0x265 },
			{ "NpcSpawn", 0x114 },
			{ "NpcSpawn2", 0x2F2 },
			{ "ActionEffect01", 0xBD },
			{ "ActionEffect08", 0x13F },
			{ "ActionEffect16", 0x390 },
			{ "ActionEffect24", 0x9E },
			{ "ActionEffect32", 0x276 },
			{ "StatusEffectList", 0x2CE },
			{ "StatusEffectList3", 0x97 },
			{ "Examine", 0x19C },
			{ "UpdateGearset", 0x3D5 },
			{ "UpdateParty", 0x16A },
			{ "ActorControl", 0x198 },
			{ "ActorCast", 0x301 },
			{ "UnknownEffect01", 0x2D9 },
			{ "UnknownEffect16", 0x127 },
			{ "ActionEffect02", 0x353 },
			{ "ActionEffect04", 0x37C }
		}
	};
}