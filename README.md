# Router Port Scanner

Android MVP for checking common TCP ports on devices you own or are authorized to test.

Default target: `192.168.0.1`
Ports: 22, 53, 80, 443, 554, 8080, 8443

## Build APK from an Android phone using GitHub Actions

1. Create a new GitHub repository.
2. Upload the contents of this project ZIP to the repository root (not the outer folder itself).
3. Open the repository's **Actions** tab.
4. Select **Build Android APK**.
5. Tap **Run workflow** and confirm.
6. When the build finishes, open that workflow run.
7. Under **Artifacts**, download **RouterPortScanner-debug-apk**.
8. Extract the downloaded artifact ZIP and install `app-debug.apk` on your Android phone.

Android may ask you to allow installing unknown apps for the browser/file manager you use. Only enable that for APKs you trust.

## Scope

This app performs TCP connection checks only. Use it only on devices/networks you own or have explicit authorization to test.
