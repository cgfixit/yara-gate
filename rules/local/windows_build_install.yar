rule win_msbuild_inline_task {
    meta:
        author = "yara-gate"
        description = "MSBuild project with an inline C# or VB task that allocates executable memory, loads an assembly from bytes, or downloads and decodes a payload"
        intent = "Advisory on a project, props, or targets file whose CodeTaskFactory or RoslynCodeTaskFactory task calls VirtualAlloc, CreateThread, a kernel32 import, Marshal.Copy, a delegate from a function pointer, or Assembly.Load, or pairs a download with base64 decoding or Process.Start. MSBuild compiles and runs the task during a build, so a cloned repository can run it. An inline task that only formats text, reads files, or starts git stays clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1127/001/"
        reference_lolbas = "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/"
        technique = "T1127.001"
    strings:
        $factory = /TaskFactory[ \t]*=[ \t]*["'](Code|RoslynCode)TaskFactory["']/ nocase ascii wide
        $code = /<Code[ \t>]/ ascii wide
        $memory = /\b(VirtualAlloc(Ex)?|VirtualProtect|CreateThread|CreateRemoteThread|WriteProcessMemory|NtAllocateVirtualMemory|GetDelegateForFunctionPointer|Marshal\.Copy|Assembly\.Load[ \t]*\(|DllImport[ \t]*\([ \t]*"kernel32)/ ascii wide
        $fetch = /\b(DownloadData|DownloadString|DownloadFile|GetByteArrayAsync|GetStringAsync|WebRequest\.Create|HttpWebRequest)\b/ ascii wide
        $run = /\b(FromBase64String|Process\.Start)\b/ ascii wide
    condition:
        $factory and $code and ($memory or ($fetch and $run))
}

rule win_inf_scriptlet_install {
    meta:
        author = "yara-gate"
        description = "Setup INF that registers scrobj.dll against a remote scriptlet, or whose pre-setup commands launch a script host or downloader"
        intent = "Advisory on the cmstp and InfDefaultInstall shape: an INF with a $chicago$ or $Windows NT$ signature whose OCX section points scrobj.dll at an HTTP(S) or UNC scriptlet, or whose RunPreSetupCommandsSection runs PowerShell, mshta, regsvr32, rundll32, certutil, bitsadmin, or a cmd /c. Connection Manager profiles that only copy files or run their own setup stay clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/003/"
        reference_lolbas = "https://lolbas-project.github.io/lolbas/Binaries/Cmstp/"
        technique = "T1218.003"
    strings:
        $signature = /\bSignature[ \t]*=[ \t]*"?\$(chicago|Windows NT)\$/ nocase ascii wide
        $scriptlet = /scrobj\.dll[ \t]*,[^\r\n]{0,24},[ \t]*["']?(https?:\/\/|\\\\)/ nocase ascii wide
        $presetup = /\[RunPreSetupCommandsSection\][ \t]*\r?\n([^\[]{0,512}\n)?[^\[\r\n]{0,64}\b(powershell|pwsh|mshta|regsvr32|rundll32|certutil|bitsadmin|wscript|cscript|cmd(\.exe)?[ \t]+\/c)\b/ nocase ascii wide
    condition:
        $signature and ($scriptlet or $presetup)
}
