import os
import json
import configparser
import argparse
import binascii

_NitroEncryptionData = None

def read_ini_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    # Add a dummy section header if none exists
    # Otherwise breaks configparser if the file doesn't have a section header
    if not content.startswith('['):
        content = '[DEFAULT]\n' + content

    config = configparser.ConfigParser()
    config.read_string(content)  # Use read_string to parse the modified content
    
    # Initialize the output structure with null values
    data = {
        "NitroEncryptionData": _NitroEncryptionData,  # Default key
        "AESHardwareConstant": None,
        "KeyX0x18": None,
        "KeyX0x1B": None,
        "KeyX0x25": None,
        "KeyX0x2C": None,
        "DevKeyX0x18": None,
        "DevKeyX0x1B": None,
        "DevKeyX0x25": None,
        "DevKeyX0x2C": None
    }
    
    # Populate the structure with values from the INI file
    if config.sections():  # Process sections if they exist
        for section in config.sections():
            for key, value in config.items(section):
                normalized_key = key.replace(" ", "").lower()  # Normalize key to lowercase for matching
                normalized_value = value.upper()  # Normalize the value to uppercase
                
                # Handle alternate key names for AESHardwareConstant
                if normalized_key in ["hardwareconstant", "generator"]:
                    normalized_key = "aeshardwareconstant"
                
                # Match normalized keys to the expected JSON structure
                for expected_key in data.keys():
                    if normalized_key == expected_key.lower():
                        data[expected_key] = normalized_value
                        break
    else:  # Process keys from the [DEFAULT] section if no other sections exist
        for key, value in config.items("DEFAULT"):
            normalized_key = key.replace(" ", "").lower()  # Normalize key to lowercase for matching
            normalized_value = value.upper()  # Normalize the value to uppercase
            
            # Handle alternate key names for AESHardwareConstant
            if normalized_key in ["hardwareconstant", "generator"]:
                normalized_key = "aeshardwareconstant"
            
            # Match normalized keys to the expected JSON structure
            for expected_key in data.keys():
                if normalized_key == expected_key.lower():
                    data[expected_key] = normalized_value
                    break
    
    return data

def read_binary_file(file_path):
    keys = [
        "AESHardwareConstant",
        "KeyX0x18",
        "KeyX0x1B",
        "KeyX0x25",
        "KeyX0x2C",
        "DevKeyX0x18",
        "DevKeyX0x1B",
        "DevKeyX0x25",
        "DevKeyX0x2C"
    ]
    data = {"NitroEncryptionData": _NitroEncryptionData}  # Initialize with default key

    with open(file_path, 'rb') as f:
        for i, key in enumerate(keys):
            line = f.read(16)  # Read 16 bytes for each key
            if not line:  # Stop if no more data
                break
            if all(b == 0 for b in line):  # Check if the line is all 00
                data[key] = None
            else:
                # Use binascii.hexlify for compatibility with older Python versions
                line = line[::-1]  # Reverse the byte order
                data[key] = binascii.hexlify(line).decode('utf-8').upper()

    return data

def compare_json(existing_data, new_data):
    """Compare existing JSON data with new data."""
    return existing_data == new_data

def convert_to_json(file_path, output_path, force_overwrite=False):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    _, ext = os.path.splitext(file_path)
    if ext == '.txt':  # Assuming .txt files are INI files
        data = read_ini_file(file_path)
    elif ext == '.bin':  # Assuming other extensions are binary files
        data = read_binary_file(file_path)
    else:
        raise ValueError("Unsupported file type. Use .txt for INI files or .bin for binary files.")
    
    if os.path.exists(output_path):
        with open(output_path, 'r') as json_file:
            existing_data = json.load(json_file)
        if compare_json(existing_data, data):
            print("The input data matches the existing JSON file. No changes made.")
            return
        elif not force_overwrite:
            print("The input data differs from the existing JSON file. Use --force to overwrite.")
            return
    
    with open(output_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Data has been converted to JSON and saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Convert INI or binary files to JSON.")
    parser.add_argument("file", help="Path to the input file (.txt for INI, others for binary).")
    parser.add_argument("--force", action="store_true", help="Force overwrite of the existing JSON file.")
    args = parser.parse_args()

    output_path = "config.json"
    convert_to_json(args.file, output_path, args.force)

if __name__ == "__main__":
    main()