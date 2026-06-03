using System.Diagnostics.CodeAnalysis;

namespace Unscrambler.Constants.Versions;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "UnusedType.Global")]
public static class GameConstants {
	[VersionConstant]
	public static VersionConstants For751() => new() {
		GameVersion = "2026.05.25.0000.0000",
		TableOffsets = [0x22DF210, 0x22EA9B0, 0x22FBB20],
		TableSizes = [11752 * 4, 17500 * 4, 21442 * 4],
		TableRadixes = [113, 125, 151],
		TableMax = [104, 140, 142],
		MidTableOffset = 0x22DEDA0,
		MidTableSize = 142 * 8,
		DayTableOffset = 0x2309DA0,
		DayTableSize = 51 * 4,
		OpcodeKeyTableSize = 143 * 4,
		OpcodeKeyTableOffset = 0x2309E70,
		ObfuscationEnabledMode = 159,
		InitZoneOpcode = 0x96,
		UnknownObfuscationInitOpcode = 0xA3,
		InitZoneLength = 168,
		ActorControlSelfLength = 72,
		FateInfoOpcode = 0x3A9,
		FateInfoLength = 56,
		FateStart = 2357,
		FateEnd = 2358,
		FateProgress = 2366,
		ObfuscatedOpcodes = new Dictionary<string, int> {
			{ "PlayerSpawn", 0x255 },
			{ "NpcSpawn", 0x26B },
			{ "NpcSpawn2", 0x242 },
			{ "ActionEffect01", 0x393 },
			{ "ActionEffect08", 0xD3 },
			{ "ActionEffect16", 0xA7 },
			{ "ActionEffect24", 0x147 },
			{ "ActionEffect32", 0x3D1 },
			{ "StatusEffectList", 0x295 },
			{ "StatusEffectList3", 0x138 },
			{ "Examine", 0x3A2 },
			{ "UpdateGearset", 0x127 },
			{ "UpdateParty", 0xEB },
			{ "ActorControl", 0x1E8 },
			{ "ActorCast", 0x2F6 },
			{ "UnknownEffect01", 0x39B },
			{ "UnknownEffect16", 0x269 },
			{ "ActionEffect02", 0x157 },
			{ "ActionEffect04", 0xEF }
		}
	};
}