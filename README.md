# NDecrypt

[![Build and Test](https://github.com/SabreTools/NDecrypt/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/SabreTools/NDecrypt/actions/workflows/build_and_test.yml)

A simple tool for simple people.

## What is this?

This is a code port of 3 different programs:

- `3ds_encrypt.py`
- `3ds_decrypt.py`
- `woodsec` (part of [wooddumper](https://github.com/TuxSH/wooddumper))

## No really, what is this?

This tool allows you to encrypt and decrypt your personally dumped NDS and N3DS roms with minimal hassle. The only caveat is that you need a `config.json`, `keys.bin`, or `aes_keys.txt` file for your personally obtained encryption keys.

## Where do I find it?

For the most recent stable build, download the latest release here: [Releases Page](https://github.com/SabreTools/NDecrypt/releases)

For the latest WIP build here: [Rolling Release](https://github.com/SabreTools/NDecrypt/releases/tag/rolling)

## So how do I use this?

    Possible values for <operation>:
    e, encrypt - Encrypt the input files
    d, decrypt - Decrypt the input files
    i, info    - Output file information

    Possible values for [flags] (one or more can be used):
    -a, --aes-keys        Enable using aes_keys.txt instead of keys.bin
    -dev, --development   Enable using development keys, if available
    -f, --force           Force operation by avoiding sanity checks
    -h, --hash            Output size and hashes to a companion file
    -k, --keyfile <path>  Path to keys.bin or aes_keys.txt
    -c, --config <path>   Path to config.json

    <path> can be any file or folder that contains uncompressed items.
    More than one path can be specified at a time.

### Notes on Running

- This overwrites the input files, so make backups if you're working on your original, personal dumps.
- Mixed folders or inputs are also accepted, you can decrypt or encrypt multiple files, regardless of their type. This being said, you can only do encrypt OR decrypt at one time.
- Required files will automatically be searched for in the application runtime directory as well as `%HOME%/.config/ndecrypt`.
- If found, `config.json` will take priority over both `keys.bin` and `aes_keys.txt`, even if `-a` and/or `-k` are defined. You've been warned.

## I feel like something is missing...

You (possibly*) are! In fact, you may be asking, "Hey, what was that `keys.bin` you mentioned??". I'm glad you asked. It's used only for Nintendo 3DS and New 3DS files. Since some people don't like reading code, you need the 9 16-bit keys in little endian format (most common extraction methods produce big endian, so keep that in mind). It's recommended that you fill with 0x00 if you don't have access to a particular value so it doesn't mess up the read. They need to be in the following order:

| `config.json` | `aes_keys.txt` | rom-properties `keys.conf` |
| --- | --- | --- |
| `NitroEncryptionData` | **UNMAPPED** | **UNMAPPED** |
| `AESHardwareConstant` | `generator` | `ctr-scrambler` |
| `KeyX0x18` | `slot0x18KeyX` | `ctr-Slot0x18KeyX` |
| `KeyX0x1B` | `slot0x1BKeyX` | `ctr-Slot0x1BKeyX` |
| `KeyX0x25` | `slot0x25KeyX` | `ctr-Slot0x25KeyX` |
| `KeyX0x2C` | `slot0x2CKeyX` | `ctr-Slot0x2CKeyX` |
| `DevKeyX0x18` | **UNMAPPED** | `ctr-dev-Slot0x18KeyX` |
| `DevKeyX0x1B` | **UNMAPPED** | `ctr-dev-Slot0x1BKeyX` |
| `DevKeyX0x25` | **UNMAPPED** | `ctr-dev-Slot0x25KeyX` |
| `DevKeyX0x2C` | **UNMAPPED** | `ctr-dev-Slot0x2CKeyX` |

The last 4 are only required if you use the `-dev` flag. Once again, don't ask for these, please. If you're missing a required key, then things won't work. Don't blame me, blame society. Or something. And no, this isn't related to whatever GodMode9 does; this is a custom format.

*If you choose to use the `-a` option, you can instead provide your personally filled out `aes_keys.txt` file in the same folder as NDecrypt and that can be used instead. Please note that if you choose to use this file, you will not be able to use the `-dev` flag. If you forget and happen to use them together, NDecrypt will disable that flag for you. You're welcome.

*If you choose to use the `-c` option, you can instead provide your personally filled out `config.json` file in the same folder as NDecrypt and that can be used instead. This does not have the same limitations as the `-a` option, but is not used or created by any other program at the moment. See [the sample config](https://github.com/SabreTools/NDecrypt/blob/master/config-default.json) that I've nicely generated for you. You're welcome. Again.

## But does it work?

As much as I'd like to think that this program is entirely without flaws, numbers need to speak for themselves sometimes. Here's a list of the supported sets and their current compatibility percentages with woodsec and the Python scripts (as of 2020-12-19):

- **Nintendo DS** -  >99% compatible (Both encryption and decryption)
- **Nintendo DSi** - 100% compatible (Both encryption and decryption)
- **Nintendo 3DS** - 100% compatible (Both encryption and decryption)
- **Nintendo New 3DS** - 100% compatible (Both encryption and decryption)

Please note the above numbers are based on the current, documented values. The notable exceptions to this tend to be unlicensed carts which may be dumped incorrectly or have odd information stored in their secure area.

## Anything else?

I'd like to thank the developers of the original programs for doing the actual hard work to figure things out. I'd also like to thank everyone who helped to test this against the original programs and made code suggestions.

## Disclaimer

This program is **ONLY** for use with personally dumped files and keys and is not meant for enabling illegal activity. I do not condone using this program for anything other than personal use and research. If this program is used for anything other than that, I cannot be held liable for anything that happens.
