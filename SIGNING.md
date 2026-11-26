# APK Signing Support

This branch adds experimental APK signing support using the same approach as AppManagerNG.

## Changes:
- Added Signer.kt for APK signing using apksig library
- Added SigSchemes.kt for v1/v2/v3/v4 signature schemes
- Added KeyStoreManager.kt for keystore management
- Integration into InstallerX install flow
