# Disposable test evidence only. A failure here forbids Docker container creation.
# Requires Windows PowerShell 5.1, NTFS DACLs, and a private local user profile.
# The caller's Windows SID, Administrators and SYSTEM are trusted principals.
# A compromised same-user process or local administrator is outside this
# local development fixture's boundary; this is no remote/daemon attestation.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class VirkiJournalNative {
  [StructLayout(LayoutKind.Sequential)]
  public struct FileInfo {
    public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh,
      WriteLow, WriteHigh, VolumeSerial, SizeHigh, SizeLow, Links, FileIndexHigh, FileIndexLow;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct DispositionInfo {
    [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern SafeFileHandle CreateFile(string name, uint access, uint share,
    IntPtr security, uint mode, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool SetFileInformationByHandle(SafeFileHandle handle,
    int infoClass, ref DispositionInfo info, uint size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
    StringBuilder buffer, uint capacity, uint flags);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint info,
    out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor,
    uint revision, uint info, out IntPtr text, out uint length);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr LocalFree(IntPtr handle);
}
'@

function Assert-Handle {
  param(
    [Microsoft.Win32.SafeHandles.SafeFileHandle] $Handle,
    [string] $Expected,
    [bool] $Strict
  )
  if ($Handle.IsInvalid -or $Handle.IsClosed) { throw 'invalid journal handle' }
  $info = New-Object VirkiJournalNative+FileInfo
  if (-not [VirkiJournalNative]::GetFileInformationByHandle($Handle, [ref]$info)) {
    throw 'journal handle identity unavailable'
  }
  if (($info.Attributes -band 0x400) -ne 0) { throw 'reparse point in journal path' }
  $buffer = New-Object System.Text.StringBuilder 32768
  $size = [VirkiJournalNative]::GetFinalPathNameByHandle($Handle, $buffer, 32768, 0)
  if ($size -eq 0 -or $size -ge 32768) { throw 'journal handle path unavailable' }
  $actual = $buffer.ToString()
  if ($actual.StartsWith('\\?\')) { $actual = $actual.Substring(4) }
  if (-not [string]::Equals($actual, [System.IO.Path]::GetFullPath($Expected),
      [StringComparison]::OrdinalIgnoreCase)) {
    throw 'journal handle/path mismatch'
  }

  $owner = [IntPtr]::Zero
  $group = [IntPtr]::Zero
  $dacl = [IntPtr]::Zero
  $sacl = [IntPtr]::Zero
  $descriptor = [IntPtr]::Zero
  $code = [VirkiJournalNative]::GetSecurityInfo($Handle, 1, 5,
    [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$descriptor)
  if ($code -ne 0 -or $descriptor -eq [IntPtr]::Zero) { throw 'journal handle ACL unavailable' }
  try {
    $text = [IntPtr]::Zero
    $length = [uint32]0
    if (-not [VirkiJournalNative]::ConvertSecurityDescriptorToStringSecurityDescriptor(
      $descriptor, 1, 5, [ref]$text, [ref]$length)) { throw 'journal handle SDDL unavailable' }
    try { $sddl = [Runtime.InteropServices.Marshal]::PtrToStringUni($text) }
    finally { [void][VirkiJournalNative]::LocalFree($text) }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $trusted = @($current, 'S-1-5-18', 'S-1-5-32-544')
    if (($Strict -and $trusted -notcontains $sd.Owner.Value) -or
        $null -eq $sd.DiscretionaryAcl) {
      throw 'journal path owner/DACL not trusted'
    }
    foreach ($ace in $sd.DiscretionaryAcl) {
      if ($ace -isnot [System.Security.AccessControl.QualifiedAce]) {
        throw 'journal path has unreviewed ACE'
      }
      if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
        continue
      }
      if (([int]$ace.AceFlags -band 8) -ne 0) {
        continue
      }
      if ($trusted -contains $ace.SecurityIdentifier.Value) { continue }
      # Ancestors may grant ordinary read/traverse and create-child (e.g.
      # C:\Users), but must not allow replacement or security mutations.
      # Private journal leaves must also deny outsider READ/LIST/READ_CONTROL:
      # the JSONL contains an unpredictable Docker owner-label token.
      $forbidden = if ($Strict) {
        # Windows PowerShell 5.1 parses high-bit hex literals as signed Int32;
        # casting 0x80020089 directly to UInt32 raises an overflow exception.
        # The decimal literal retains the exact security mask (0x80020089).
        [uint32]0xD0156 -bor [uint32]2147614857
      } else { [uint32]0xD0040 }
      $forbidden = $forbidden -bor [uint32]0x50000000
      $rights = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ace.AccessMask), 0)
      if (($rights -band $forbidden) -ne 0) {
        throw 'journal path accessible by untrusted principal'
      }
    }
  } finally {
    [void][VirkiJournalNative]::LocalFree($descriptor)
  }
}

function Open-GuardedDirectory([string]$Directory, [bool]$Strict) {
  $h = [VirkiJournalNative]::CreateFile($Directory, 0x20080, 3,
    [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
  Assert-Handle $h $Directory $Strict
  return $h
}

function New-PrivateDirectory([string]$Directory) {
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($entry in @($sid,
    (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'),
    (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $entry, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  [void][System.IO.Directory]::CreateDirectory($Directory, $acl)
}

$handles = New-Object 'System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
try {
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  if (@('create', 'append', 'remove') -notcontains $args[0]) { throw 'invalid journal operation' }
  $operation = $args[0]
  if ($request.name -cnotmatch '^virki-offline-fixture-[a-f0-9]{32}$' -or
      $request.owner -cne $request.name.Substring(22) -or
      [string]::IsNullOrEmpty($request.directory)) {
    throw 'invalid journal identity'
  }
  $directory = [IO.Path]::GetFullPath([string]$request.directory)
  $profile = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile'))
  if (-not $directory.StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'journal outside user profile'
  }
  if ($directory -match '^\\\\' -or $directory -match '^\\\\\?\\') {
    throw 'network/device journal forbidden'
  }
  # Pin every ancestor with handles denying FILE_SHARE_DELETE throughout the
  # entire journal transaction. No path-based lstat->realpath->open gap.
  $parts = New-Object 'System.Collections.Generic.List[string]'
  $p = $directory
  while ($true) {
    $parts.Add($p)
    $parent = [IO.Path]::GetDirectoryName($p)
    if ([string]::IsNullOrEmpty($parent) -or $parent -eq $p) { break }
    $p = $parent
  }
  $parts.Reverse()
  foreach ($part in $parts) {
    $strict = $part.StartsWith($profile, [StringComparison]::OrdinalIgnoreCase)
    if (-not [IO.Directory]::Exists($part)) {
      if (-not $strict) { throw 'missing system journal ancestor' }
      New-PrivateDirectory $part
    }
    $h = Open-GuardedDirectory $part $strict
    $handles.Add($h)
  }
  $file = [IO.Path]::Combine($directory, $request.name + '.jsonl')
  if ($operation -eq 'remove') {
    # A DeleteOnClose FileStream would delete before verifying the actual file
    # handle. Open the reparse point itself, validate its owner/ACL/identity,
    # and only then mark that exact verified handle for deletion.
    $h = [VirkiJournalNative]::CreateFile($file, 0x30080, 0,
      [IntPtr]::Zero, 3, 0x00200000, [IntPtr]::Zero)
    try {
      Assert-Handle $h $file $true
      $disposition = New-Object VirkiJournalNative+DispositionInfo
      $disposition.DeleteFile = $true
      if (-not [VirkiJournalNative]::SetFileInformationByHandle($h, 4,
          [ref]$disposition, [Runtime.InteropServices.Marshal]::SizeOf($disposition))) {
        throw 'verified journal handle could not be deleted'
      }
    } finally { $h.Dispose() }
  } else {
    $mode = if ($operation -eq 'create') { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Open }
    $stream = New-Object System.IO.FileStream($file, $mode,
      [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try {
      Assert-Handle $stream.SafeFileHandle $file $true
      $bytes = [Text.Encoding]::UTF8.GetBytes(([string]$request.line) + "`n")
      if ($operation -eq 'append') { [void]$stream.Seek(0, [IO.SeekOrigin]::End) }
      $stream.Write($bytes, 0, $bytes.Length)
      $stream.Flush($true)
      Assert-Handle $stream.SafeFileHandle $file $true
    } finally { $stream.Dispose() }
  }
  [Console]::Out.Write('JOURNAL_OK')
} catch {
  [Console]::Error.Write('Windows reconciliation journal identity/ACL binding unavailable.')
  exit 3
} finally {
  for ($i = $handles.Count - 1; $i -ge 0; $i--) { $handles[$i].Dispose() }
}
