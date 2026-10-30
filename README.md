# Wireshark VR

A network packet analyzer for VR, inspired by Wireshark's interface. Packet lists, protocol details and raw bytes float around you as movable windows, and it runs as a standalone app on Meta Quest with no PC or Quest Link.

> **Independent project.** This is not affiliated with, endorsed by, or sponsored by the Wireshark Foundation or the Wireshark project. "Wireshark" is a trademark of the Wireshark Foundation and is used here only to describe what this project is inspired by and works with.

## Features

- **Packet List, Packet Details and Packet Bytes** windows, with Wireshark-style row colouring
- **Display filters** with a floating keyboard, field suggestions and recent filters
- **Headset traffic capture** on a standalone Quest, over IPv4 and IPv6, saved as `.pcap` files
- **Streaming** with pause, so you can page through packets while new ones wait in a queue
- **Capture Overview** showing the protocol mix and a clickable traffic graph
- **Expert Info**, packet marking, Follow Stream, and protocol, conversation and endpoint statistics
- **3D flow graph** of a conversation, and a Guide mode that explains each pane in plain English
- A squeaky stress ball, for when the retransmissions get to you

## Requirements

- Meta Quest headset with Developer Mode enabled in the Meta Horizon phone app (developed and tested on Quest 3)
- .NET 10 SDK with the `android` workload, and the Android SDK
- Visual Studio 2026 is optional
- [Wireshark](https://www.wireshark.org/) is optional, and only used on the PC build for full-fidelity dissection through `tshark`

## Run it on a Quest

Connect the headset over USB and accept the USB debugging prompt inside it.

**Visual Studio:** open `WiresharkVR.slnx`, set **WiresharkVR.App.Android** as the startup project, choose your Quest in the device list, and press Run.

**Command line:**

```powershell
dotnet build WiresharkVR.App\Projects\Android\WiresharkVR.App.Android.csproj -t:Run "-p:AndroidSdkDirectory=C:\Program Files (x86)\Android\android-sdk"
```

The app appears on the headset under **Library > Unknown Sources**. After installing, it no longer needs the PC.

## Run it on a PC

No headset is needed for the desktop simulator:

```powershell
dotnet run --project WiresharkVR.App -- --sim
```

Add `--native` to use the built-in dissector even when `tshark` is installed, or pass a path to open a capture file.

## Controls

| Control | Action |
|---|---|
| Trigger | Press what you are pointing at |
| Grip | Move the window you are pointing at |
| Stick | Scroll the window you last pointed at |
| A or X | Pause or resume a stream |
| B or Y | Show or hide the keyboard |

## Capturing headset traffic

Open **Capture > Capture this headset's traffic**. The Quest does not let apps listen to the network directly, so capture uses Android's VPN service: traffic passes through the app, which records it and sends it on. Nothing is sent to a remote VPN server.

You may need to accept a VPN permission prompt. The first time, it may take you out of the app.

## Privacy

Captures can contain sensitive information. Most traffic is encrypted, but a capture can still show which sites and services were contacted, and any traffic that was not encrypted is stored in full.

- Files are saved in the app's folder on the headset as `headset-<date>-<time>.pcap`, and each can reach 256 MB.
- Only capture devices and networks you own or have permission to monitor.
- Do not publish a capture without reviewing it. This repository ignores everything in `samples/` except the bundled sample.

## Known limitations

- Only TCP and UDP are forwarded during capture. Other traffic, such as ping, is recorded but goes no further.
- The app rebuilds traffic as it passes through, so packet sizes, timing and retransmissions reflect the tunnel rather than the Wi-Fi network.
- Headset capture sees only the headset's own traffic, not other devices on the network.
- Capture has not been tested under heavy load, and speeds may drop while it runs.
- Filters cannot be applied during a stream. Stop it first.
- The built-in dissector covers Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS and HTTP. Everything else is listed with its raw bytes.
- Live capture on the PC through `tshark` is unfinished and has not been tested.
- The packet boxes in the 3D flow graph respond to hand pinches, not the controller pointer.

## Project layout

| Folder | Contents |
|---|---|
| `WiresharkVR.Core` | Capture reading, dissector, display filters, `tshark` runner and the VPN forwarder |
| `WiresharkVR.App` | The StereoKit VR interface and platform code |
| `WiresharkVR.Core.Tests` | xUnit tests, including real-socket forwarder tests |

Run the tests with `dotnet test WiresharkVR.Core.Tests`.

## License

[MIT](LICENSE). When used on a PC, this project can run a separately installed copy of `tshark`, which is distributed by the Wireshark project under its own license. Built with [StereoKit](https://stereokit.net/).
