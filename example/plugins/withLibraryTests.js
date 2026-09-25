const { withPodfile } = require('expo/config-plugins');

// Registers the library pod with its XCTest spec so the Pods project gets a
// react-native-ecc-csr-Unit-Tests scheme. use_expo_modules! skips pods that are already declared,
// so this declaration replaces the autolinked one. includeTests would do the same for every pod,
// including ExpoModulesCore, whose tests need extra dependencies.
const POD = "  pod 'react-native-ecc-csr', :path => '../../ios', :testspecs => ['Tests']";

module.exports = function withLibraryTests(config) {
  return withPodfile(config, (config) => {
    const { contents } = config.modResults;
    if (!contents.includes(POD)) {
      config.modResults.contents = contents.replace(/^(\s*)use_expo_modules!/m, `${POD}\n$1use_expo_modules!`);
    }
    return config;
  });
};
