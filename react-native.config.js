module.exports = {
  dependency: {
    platforms: {
      android: {
        packageInstance: 'new com.ecccsr.CSRPackage()'
      },
      ios: {
        project: './ios/CSRModule.xcodeproj',
      },
    }
  }
};
