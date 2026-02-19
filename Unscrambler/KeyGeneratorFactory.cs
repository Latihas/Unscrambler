using Unscrambler.Constants;
using Unscrambler.Derivation;
using Unscrambler.Derivation.Versions;

namespace Unscrambler;

public abstract class KeyGeneratorFactory {
    public static IKeyGenerator ForGameVersion(string gameVersion) {
        if (VersionConstants.Constants.TryGetValue(gameVersion, out var constants))
            return Create(constants);
        throw new ArgumentException($"Unsupported game version: {gameVersion}");
    }

    public static IKeyGenerator WithConstants(VersionConstants constants, string tableBinaryBasePath) => Create(constants, tableBinaryBasePath);

    public static IKeyGenerator WithConstants(VersionConstants constants, byte[] table0, byte[] table1, byte[] table2, byte[] midTable, byte[] dayTable, byte[]? opcodeKeyTable = null) =>
        Create(constants, table0, table1, table2, midTable, dayTable, opcodeKeyTable);

    private static IKeyGenerator GetKeyGenerator(VersionConstants _) => new KeyGenerator74();


    private static IKeyGenerator Create(VersionConstants constants, string? tableBinaryBasePath = null) {
        var keyGenerator = GetKeyGenerator(constants);
        keyGenerator.Initialize(constants, tableBinaryBasePath);
        return keyGenerator;
    }

    private static IKeyGenerator Create(VersionConstants constants, byte[] table0, byte[] table1, byte[] table2, byte[] midTable, byte[] dayTable, byte[]? opcodeKeyTable = null) {
        var keyGenerator = GetKeyGenerator(constants);
        keyGenerator.Initialize(constants, table0, table1, table2, midTable, dayTable, opcodeKeyTable);
        return keyGenerator;
    }
}