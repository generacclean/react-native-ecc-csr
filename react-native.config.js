module.exports = {
  dependency: {
    platforms: {
      android: {
        packageImportPath: 'import com.ecccsr.CSRPackage;',
        packageInstance: 'new CSRPackage()'
      },
      ios: {
        project: './ios/CSRModule.xcodeproj',
      },
    }
  }
};
