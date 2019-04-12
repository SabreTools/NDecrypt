# NDecrypt

A simple tool for simple people.

## What is this?

This is a code port of 3 different programs:

- `3ds_encrypt.py`
- `3ds_decrypt.py`
- `woodsec` (part of [wooddumper](https://github.com/TuxSH/wooddumper))

## No really, what is this?

This tool allows you to encrypt and decrypt your personally dumped NDS and N3DS roms with minimal hassle. The only caveat right now is that you need a `keys.bin` file for your personally obtained encryption keys. See the code for the order and details there. Please don't ask for the keys.

## So how do I use this?

	NDecrypt.exe <flag> [-dev] <file|dir> ...

	Possible values for <flag>:
	encrypt, e - Encrypt the incoming files
	decrypt, d - Decrypt the incoming files


**Note:** This overwrites the incoming files, so make backups if you're working on your original, personal dumps.
**Note:** Mixed folders or inputs are also accepted, you can decrypt or encrypt multiple files, regardless of their type. This being said, you can only do encrypt OR decrypt at one time.

## Anything else?

I'd like to thank the developers of the original programs for doing the actual hard work to figure things out. I'd also like to thank everyone who helped to test this against the original programs and made code suggestions.

Unofficially, this is entirely, 100% FOSS, no strings attached. I keep forgetting what license that is.