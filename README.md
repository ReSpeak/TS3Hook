# Teamspeak 3 Hook [![](https://img.shields.io/github/release/ReSpeak/TS3Hook.svg?style=flat-square)](../../releases/latest) [![](https://img.shields.io/github/downloads/ReSpeak/TS3Hook/total.svg?style=flat-square)]()

## What is this?

This is a TS3Client Plugin that decrypts Teamspeak 3 command packets on the fly and displays them in Teamspeak's own Console.

## Features

- Shows incoming/outgoing command packets of your client.
- Ability to hide certain commands to keep focusing on the important stuff.
- Ability to block certain outgoing commands to [hide your connectioninfo](https://github.com/ReSpeak/TS3Hook/issues/14) for example.
- Ability to send own commands through your client.

## How to use

1. Download and install the [latest release](https://github.com/ReSpeak/TS3Hook/releases/latest) for your client.
2. Add `-console` to the startup parameters of your TS3Client shortcut. ([Screenshot](https://i.imgur.com/a5HgomX.png))
3. Start your Teamspeak 3 Client with the modified shortcut.
4. Take a look at the console named `Teamspeak 3 Client`.
5. OPTIONAL: Edit the `HookConf.ini` in the root directory of your TS3 binary to your needs.
6. Profit

NOTE: You can also inject the DLL with the injector of the latest release.

## Injection

Send a chat message with `~cmd` and append a command where ` ` (spaces) are replaced with `~s`.  
Example:  
`~cmdsendtextmessage~stargetmode=2~smsg=hi`  
to send  
`sendtextmessage targetmode=2 msg=hi`



<details><summary>Screenshots</summary>

![](https://i.imgur.com/uBjPUcc.png)
![](https://i.imgur.com/0ZlwlQO.png)
</details>
