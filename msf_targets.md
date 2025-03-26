# BlueKeep Exploit Target Selection Guide

## Target ID Options

When using the BlueKeep exploit in Metasploit, choosing the correct TARGET value is crucial for successful exploitation. Different target IDs correspond to different versions of vulnerable Windows systems.

### Available Target IDs

| ID | Operating System | Notes |
|----|------------------|-------|
| 0  | Automatic targeting | May not work correctly in all cases |
| 1  | Windows 7 SP1 (6.1.7601 x64) | Common in corporate environments |
| 2  | Windows 7 SP0 (6.1.7600 x64) | **RECOMMENDED** - Most reliable for testing |
| 3  | Windows Server 2008 R2 SP1 (6.1.7601 x64) | Requires fDisableCam=0 |
| 4  | Windows Server 2008 R2 SP0 (6.1.7600 x64) | Requires fDisableCam=0 |
| 5  | Windows Server 2008 SP1 (6.0.6001 x64) | Requires fDisableCam=0 |

## Recommendations

1. **For most testing scenarios**: Use target ID 2 (Windows 7 SP0)
   ```
   set TARGET 2
   ```

2. **When targeting known Windows 7 SP1 machines**:
   ```
   set TARGET 1
   ```

3. **When targeting Windows 2008 Server**: First ensure fDisableCam=0 is set in the registry
   ```
   set TARGET 3  # or 4, 5 depending on the exact version
   ```

## Notes on Windows Server 2008 Targets

For Windows Server 2008 targets (IDs 3, 4, 5), the exploit requires that the `fDisableCam` registry key is set to 0. This setting is related to the Camera and Multimedia Redirection feature in Remote Desktop Services.

Without this setting, you will likely get the following error:
