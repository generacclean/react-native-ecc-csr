// Learn more https://docs.expo.io/guides/customizing-metro
const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const config = getDefaultConfig(__dirname);

// The library's own devDependencies install a second react and react-native in ../node_modules.
// Bundling both breaks at runtime, so only this app's copies are allowed.
config.resolver.blockList = [
  ...Array.from(config.resolver.blockList ?? []),
  new RegExp(path.resolve('..', 'node_modules', 'react')),
  new RegExp(path.resolve('..', 'node_modules', 'react-native')),
];

config.resolver.nodeModulesPaths = [
  path.resolve(__dirname, './node_modules'),
  path.resolve(__dirname, '../node_modules'),
];

// Resolve the library from the repo root rather than a published copy, so the app always runs
// the source under review.
config.resolver.extraNodeModules = {
  '@generacclean/react-native-ecc-csr': '..',
};

config.watchFolders = [path.resolve(__dirname, '..')];

module.exports = config;
