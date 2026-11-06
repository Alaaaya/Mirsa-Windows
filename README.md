# Mirsa for Windows

An independent USB installer for Mirsa. Windows 10/11 x64, Apple USB drivers, an unlocked iPhone and an Apple Account are required.

## Before using

Install Apple's device support software if Windows cannot see the phone. Connect by USB, unlock the phone and approve Trust. Follow the phone's Developer Mode instructions when prompted. Free-account signing is subject to Apple's normal expiry, device and app limits. This tool does not bypass them.

## Flow

Choose your connected iPhone, enter your Apple Account, and install Mirsa from its official feed. The installer signs the app using your account and transfers its pairing record.

Automatic account handoff needs a compatible Mirsa build. Open Mirsa once on the phone, then use Finish setup in Windows. Mirsa generates a fresh public-key request. Windows encrypts the credentials for that request and transfers only encrypted bytes. Mirsa validates the session and expiry, stores the account in iOS Keychain, and deletes the one-time handoff. Windows only reports account setup complete after a consumption receipt.

The released iOS build may not yet support this protocol. The implementation is isolated on the `kat/windows-handoff` branch of Mirsa-iOS, not merged or published. Installing today's released IPA must not be represented as verified automatic login. You can still use pairing export and finish sign-in directly on the phone.

No password is intentionally written to Windows logs or settings. Credentials remain temporarily in process memory for signing and optional handoff; close the application when finished. Treat an exported pairing file as a sensitive credential. Do not share it.

The app is unsigned for Windows SmartScreen unless the owner separately arranges code signing. No Apple password should ever be supplied to an untrusted binary.

## Development

Install Node.js 22, stable Rust, Windows C++ build tools, Perl and Make. Then run `npm ci` and `npm run tauri build -- --bundles nsis,msi`.

The Windows validation workflow builds NSIS and MSI installers, packages a portable ZIP with mirsa.exe and any build-produced DLLs, verifies embedded Mirsa icons and MSI metadata, and uploads checksummed Actions artifacts. Release publication is a separate authorized step.

The portable ZIP needs all its files extracted before running mirsa.exe. WebView2 Runtime and Apple device support are system prerequisites. Frontend assets are embedded. Portable settings still use the normal Windows app-data and credential locations.

All three distributions are unsigned. Smart App Control or other Windows protections may block the MSI, NSIS installer, or portable executable. A different package format does not guarantee compatibility, and this release does not disable or bypass security controls. Real-device installation and Apple authentication must be tested separately, not inferred from a successful build.

See THIRD_PARTY_NOTICES.md for attribution. This project is not affiliated with Apple or the maintainers of its upstream libraries.
