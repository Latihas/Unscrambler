using System.Linq;
using Unscrambler.Constants;
using Unscrambler.Unscramble;
using Unscrambler.Unscramble.Versions;

namespace Unscrambler;

public abstract class UnscramblerFactory {
	public static IUnscrambler ForGameVersion(string gameVersion) {
		if (!VersionConstants.Constants.TryGetValue(gameVersion, out var constants)) constants = VersionConstants.Constants.Values.First();
		var unscrambler = new Unscrambler73();
		unscrambler.Initialize(constants);
		return unscrambler;
	}
}