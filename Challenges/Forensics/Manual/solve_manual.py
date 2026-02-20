import re
import base64

filepath = '/home/kali/Desktop/CTF_HTB/Challenges/Forensics/Manual/tradesman_manual.bat'

with open(filepath, 'r') as f:
    content = f.read()

# Dictionary to store variable values
vars_dict = {}

# Regex to find the set commands
# Pattern: !qoz! %...%c%...%c%...%c%...%=VALUE
# The variable name is split into characters.
# Example: !qoz! %FTW%b%FTW%y%FTW%o%FTW%=AaQBr...
# We need to extract 'byo' and 'AaQBr...'

lines = content.splitlines()
for line in lines:
    if line.startswith('!qoz!'):
        # Remove !qoz! 
        rest = line[5:].strip()
        if '=' in rest:
            lhs, rhs = rest.split('=', 1)
            # Parse LHS to get variable name
            # LHS looks like %FTW%b%FTW%y%FTW%o%FTW%
            # We want to extract the characters that are NOT inside %...%
            # Actually, the characters are interleaved.
            # Let's just remove anything matching %[^%]+%
            var_name = re.sub(r'%[^%]+%', '', lhs)
            vars_dict[var_name] = rhs.strip()

# Find the long line with all variables
# It looks like %qdu%%ssf%%gfw%...
# It's likely the one with many %...% sequences
long_line = ""
for line in lines:
    if line.count('%') > 50 and '!qoz!' not in line:
        long_line = line.strip()
        break

if not long_line:
    print("Could not find the long line.")
    exit()

# Extract variable names from the long line
# The line is %var1%%var2%%var3%...
# We can split by '%' and take every other element?
# %var1% -> ['', 'var1', '']
# %var1%%var2% -> ['', 'var1', '', 'var2', '']
parts = long_line.split('%')
# Filter out empty strings
var_sequence = [p for p in parts if p]

# Concatenate values
full_string = ""
for var in var_sequence:
    if var in vars_dict:
        full_string += vars_dict[var]
    else:
        # Some variables might not be in the dict if they are system vars or I missed something
        # But looking at the file, they seem to be the ones defined.
        # print(f"Warning: Variable {var} not found.")
        pass

print("Reconstructed Script:")
# print(full_string)

# Extract the Base64 string
# It is between "$s='" and "'.Replace"
start_marker = "$s='"
end_marker = "'.Replace"

if start_marker in full_string and end_marker in full_string:
    start_idx = full_string.find(start_marker) + len(start_marker)
    end_idx = full_string.find(end_marker, start_idx)
    b64_str = full_string[start_idx:end_idx]
    
    # Remove junk
    junk = 'djlrttmeqqkr'
    clean_b64 = b64_str.replace(junk, '')
    
    print(f"Clean Base64 length: {len(clean_b64)}")
    
    try:
        # The script says [Text.Encoding]::Unicode.GetString(...)
        # Unicode in PowerShell usually means UTF-16LE
        decoded = base64.b64decode(clean_b64).decode('utf-16')
        print("\nDecoded PowerShell Script:")
        print(decoded)
        
        # Save to file for analysis
        with open('/home/kali/Desktop/CTF_HTB/Challenges/Forensics/Manual/decoded_stage2.ps1', 'w') as f:
            f.write(decoded)
            
    except Exception as e:
        print(f"Error decoding: {e}")
else:
    print("Could not find Base64 string markers.")

