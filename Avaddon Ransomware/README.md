# Avaddon Ransomware

Sample hash: 1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2

# Decrypt string

## Idea
- We can see that all encrypted strings were located in .rdata section, these functions should be like this:

```txt
.text:00A21020
.text:00A21020 sub_A21020      proc near               ; DATA XREF: .rdata:00AA4398↓o
.text:00A21020                                         ; FFDD4398↓o
.text:00A21020                 push    4Ch ; 'L'       ; Size
.text:00A21022                 push    offset aFaajgxggfqotah ; "FAAJGxgGFQoTAh4kNSA0ICk7ExgeISsgODQTBDo"...
.text:00A21027                 mov     ecx, offset dword_AD504C ; void *
.text:00A2102C                 call    sub_A27F00
.text:00A21031                 push    offset sub_A9AB20 ; void (__cdecl *)()
.text:00A21036                 call    _atexit
.text:00A2103B                 pop     ecx
.text:00A2103C                 retn
.text:00A2103C s
```

- The first address of each functions is always the size of encrypted string, the following address is a value of this encrypted string. So I can take them and decrypt it by enumerating each address of these functions in .rdata, then decrypt it.
- The algorthim is simple, it can be describled this:
1. Decoding the encrypted string by base64 algorthim.
2. XORing with 2, then adding with 4 and finally XORing with 0x49.

- Here is a pseudo-code about the decryption code:

```c++
Avaddon_base64_decode();
LOBYTE(v20) = 1;
v3 = v14;
v4 = v14;
if ( v16 >= 0x10 )
  v3 = (void **)v14[0];
if ( v16 >= 0x10 )
  v4 = (void **)v14[0];
if ( v4 != (void **)((char *)v3 + v15) )
{
  v5 = (void **)((char *)v3 + v15);
  do
  {
    sub_A2C280(v12, ((*(_BYTE *)v4 ^ 2) + 4) ^ 0x49);
    v4 = (void **)((char *)v4 + 1);
  }
  while ( v4 != v5 );
  v2 = v10;
}
```

- It can be decrypted automatelly by using IDAPython, the script I uploaded in this project. Here is the result:

```txt
.rdata:00AA4398                 dd offset sub_A21020    ; DECRYPTED: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
.rdata:00AA439C                 dd offset sub_A21040    ; DECRYPTED: EnableLinkedConnections
.rdata:00AA43A0                 dd offset sub_A21060    ; DECRYPTED: EnableLUA
.rdata:00AA43A4                 dd offset sub_A21080    ; DECRYPTED: ConsentPromptBehaviorAdmin
.rdata:00AA43A8                 dd offset sub_A210A0    ; DECRYPTED: SYSTEMDRIVE
.rdata:00AA43AC                 dd offset sub_A210C0    ; DECRYPTED: PROGRAMFILES(x86)
.rdata:00AA43B0                 dd offset sub_A210E0    ; DECRYPTED: USERPROFILE
.rdata:00AA43B4                 dd offset sub_A21100    ; DECRYPTED: ProgramData
.rdata:00AA43B8                 dd offset sub_A21120    ; DECRYPTED: Program Files
.rdata:00AA43BC                 dd offset sub_A21140    ; DECRYPTED: ALLUSERSPROFILE
.rdata:00AA43C0                 dd offset sub_A21160    ; DECRYPTED: AppData
.rdata:00AA43C4                 dd offset sub_A21180    ; DECRYPTED: PUBLIC
.rdata:00AA43C8                 dd offset sub_A211A0    ; DECRYPTED: TMP
.rdata:00AA43CC                 dd offset sub_A211C0    ; DECRYPTED: Tor Browser
.rdata:00AA43D0                 dd offset sub_A211E0    ; DECRYPTED: MSOCache
.rdata:00AA43D4                 dd offset sub_A21200    ; DECRYPTED: EFI
.rdata:00AA43D8                 dd offset sub_A21220    ; DECRYPTED: \Windows
.rdata:00AA43DC                 dd offset sub_A21240    ; DECRYPTED: \Program Files
.rdata:00AA43E0                 dd offset sub_A21260    ; DECRYPTED: \Users\All Users
.rdata:00AA43E4                 dd offset sub_A21280    ; DECRYPTED: \AppData
.rdata:00AA43E8                 dd offset sub_A212A0    ; DECRYPTED: \Microsoft\Windows
.rdata:00AA43EC                 dd offset sub_A212C0    ; DECRYPTED: wmic SHADOWCOPY DELETE /nointeractive
.rdata:00AA43F0                 dd offset sub_A212E0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP
.rdata:00AA43F4                 dd offset sub_A21300    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
.rdata:00AA43F8                 dd offset sub_A21320    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
.rdata:00AA43FC                 dd offset sub_A21340    ; DECRYPTED: vssadmin Delete Shadows /All /Quiet
.rdata:00AA4400                 dd offset sub_A21360    ; DECRYPTED: bcdedit /set {default} recoveryenabled No
.rdata:00AA4404                 dd offset sub_A21380    ; DECRYPTED: bcdedit /set {default} bootstatuspolicy ignoreallfailures
.rdata:00AA4408                 dd offset sub_A213A0    ; DECRYPTED: .vhd
.rdata:00AA440C                 dd offset sub_A213C0    ; DECRYPTED: .vhdx
.rdata:00AA4410                 dd offset sub_A213E0    ; DECRYPTED: powershell Dismount-DiskImage -ImagePath
.rdata:00AA4414                 dd offset sub_A21400    ; DECRYPTED: powershell.exe
.rdata:00AA4418                 dd offset sub_A21420    ; DECRYPTED: _readme_.txt
.rdata:00AA441C                 dd offset sub_A21440    ; DECRYPTED: HOMEDRIVE
.rdata:00AA4420                 dd offset sub_A21460    ; DECRYPTED: HOMEPATH
.rdata:00AA4424                 dd offset sub_A21480    ; DECRYPTED: Desktop\
.rdata:00AA4428                 dd offset sub_A214A0    ; DECRYPTED: Control Panel\Desktop
.rdata:00AA442C                 dd offset sub_A214C0    ; DECRYPTED: WallPaper
.rdata:00AA4430                 dd offset sub_A214E0    ; DECRYPTED: {{id}}
.rdata:00AA4434                 dd offset sub_A21500    ; DECRYPTED: {{ext}}
.rdata:00AA4438                 dd offset sub_A21520    ; DECRYPTED: update
.rdata:00AA443C                 dd offset sub_A21540    ; DECRYPTED: Global\{A86668A3-8F20-41F3-97D1-676B2AD6ADF7}
.rdata:00AA4440                 dd offset sub_A21560    ; DECRYPTED: \Program Files\Microsoft\Exchange Server
.rdata:00AA4444                 dd offset sub_A21580    ; DECRYPTED: \Program Files (x86)\Microsoft\Exchange Server
.rdata:00AA4448                 dd offset sub_A215A0    ; DECRYPTED: \Program Files\Microsoft SQL Server
.rdata:00AA444C                 dd offset sub_A215C0    ; DECRYPTED: \Program Files (x86)\Microsoft SQL Server
.rdata:00AA4450                 dd offset sub_A215E0    ; DECRYPTED: \Program Files\mysql
.rdata:00AA4454                 dd offset sub_A21600    ; DECRYPTED: \Program Files (x86)\mysql
.rdata:00AA4458                 dd offset sub_A21620    ; DECRYPTED: ROOT\CIMV2
.rdata:00AA445C                 dd offset sub_A21640    ; DECRYPTED: WQL
.rdata:00AA4460                 dd offset sub_A21660    ; DECRYPTED: SELECT * FROM Win32_PerfFormattedData_PerfProc_Process
.rdata:00AA4464                 dd offset sub_A21680    ; DECRYPTED: Name
.rdata:00AA4468                 dd offset sub_A216A0    ; DECRYPTED: IDProcess
.rdata:00AA446C                 dd offset sub_A216C0    ; DECRYPTED: PercentProcessorTime
.rdata:00AA4470                 dd offset sub_A216E0    ; DECRYPTED: svchost
.rdata:00AA4474                 dd offset sub_A21700    ; DECRYPTED: csrss
.rdata:00AA4478                 dd offset sub_A21720    ; DECRYPTED: services
.rdata:00AA447C                 dd offset sub_A21740    ; DECRYPTED: lsass
.rdata:00AA4480                 dd offset sub_A21760    ; DECRYPTED: winlogon
.rdata:00AA4484                 dd offset sub_A21780    ; DECRYPTED: spoolsv
.rdata:00AA4488                 dd offset sub_A217A0    ; DECRYPTED: explorer
.rdata:00AA448C                 dd offset sub_A217C0    ; DECRYPTED: RuntimeBroker
.rdata:00AA4490                 dd offset sub_A217E0    ; DECRYPTED: System
.rdata:00AA4494                 dd offset sub_A21800    ; DECRYPTED: powershell
.rdata:00AA4498                 dd offset sub_A21820    ; DECRYPTED: wscript
.rdata:00AA449C                 dd offset sub_A21840    ; DECRYPTED: Create
.rdata:00AA44A0                 dd offset sub_A21860    ; DECRYPTED: Win32_Process
.rdata:00AA44A4                 dd offset sub_A21880    ; DECRYPTED: CommandLine
.rdata:00AA44A8                 dd offset sub_A218A0    ; DECRYPTED: -safe
.rdata:00AA44AC                 dd offset sub_A218C0    ; DECRYPTED: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
.rdata:00AA44B0                 dd offset sub_A218E0    ; DECRYPTED: explorer.exe,
.rdata:00AA44B4                 dd offset sub_A21900    ; DECRYPTED: Shell
.rdata:00AA44B8                 dd offset sub_A21920    ; DECRYPTED: bcdedit /set safeboot network
.rdata:00AA44BC                 dd offset sub_A21940    ; DECRYPTED: bcdedit /deletevalue safeboot
.rdata:00AA44C0                 dd offset sub_A21960
.rdata:00AA44C4                 dd offset sub_A21980    ; DECRYPTED: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
.rdata:00AA44C8                 dd offset sub_A219A0    ; DECRYPTED: EnableLinkedConnections
.rdata:00AA44CC                 dd offset sub_A219C0    ; DECRYPTED: EnableLUA
.rdata:00AA44D0                 dd offset sub_A219E0    ; DECRYPTED: ConsentPromptBehaviorAdmin
.rdata:00AA44D4                 dd offset sub_A21A00    ; DECRYPTED: SYSTEMDRIVE
.rdata:00AA44D8                 dd offset sub_A21A20    ; DECRYPTED: PROGRAMFILES(x86)
.rdata:00AA44DC                 dd offset sub_A21A40    ; DECRYPTED: USERPROFILE
.rdata:00AA44E0                 dd offset sub_A21A60    ; DECRYPTED: ProgramData
.rdata:00AA44E4                 dd offset sub_A21A80    ; DECRYPTED: Program Files
.rdata:00AA44E8                 dd offset sub_A21AA0    ; DECRYPTED: ALLUSERSPROFILE
.rdata:00AA44EC                 dd offset sub_A21AC0    ; DECRYPTED: AppData
.rdata:00AA44F0                 dd offset sub_A21AE0    ; DECRYPTED: PUBLIC
.rdata:00AA44F4                 dd offset sub_A21B00    ; DECRYPTED: TMP
.rdata:00AA44F8                 dd offset sub_A21B20    ; DECRYPTED: Tor Browser
.rdata:00AA44FC                 dd offset sub_A21B40    ; DECRYPTED: MSOCache
.rdata:00AA4500                 dd offset sub_A21B60    ; DECRYPTED: EFI
.rdata:00AA4504                 dd offset sub_A21B80    ; DECRYPTED: \Windows
.rdata:00AA4508                 dd offset sub_A21BA0    ; DECRYPTED: \Program Files
.rdata:00AA450C                 dd offset sub_A21BC0    ; DECRYPTED: \Users\All Users
.rdata:00AA4510                 dd offset sub_A21BE0    ; DECRYPTED: \AppData
.rdata:00AA4514                 dd offset sub_A21C00    ; DECRYPTED: \Microsoft\Windows
.rdata:00AA4518                 dd offset sub_A21C20    ; DECRYPTED: wmic SHADOWCOPY DELETE /nointeractive
.rdata:00AA451C                 dd offset sub_A21C40    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP
.rdata:00AA4520                 dd offset sub_A21C60    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
.rdata:00AA4524                 dd offset sub_A21C80    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
.rdata:00AA4528                 dd offset sub_A21CA0    ; DECRYPTED: vssadmin Delete Shadows /All /Quiet
.rdata:00AA452C                 dd offset sub_A21CC0    ; DECRYPTED: bcdedit /set {default} recoveryenabled No
.rdata:00AA4530                 dd offset sub_A21CE0    ; DECRYPTED: bcdedit /set {default} bootstatuspolicy ignoreallfailures
.rdata:00AA4534                 dd offset sub_A21D00    ; DECRYPTED: .vhd
.rdata:00AA4538                 dd offset sub_A21D20    ; DECRYPTED: .vhdx
.rdata:00AA453C                 dd offset sub_A21D40    ; DECRYPTED: powershell Dismount-DiskImage -ImagePath
.rdata:00AA4540                 dd offset sub_A21D60    ; DECRYPTED: powershell.exe
.rdata:00AA4544                 dd offset sub_A21D80    ; DECRYPTED: _readme_.txt
.rdata:00AA4548                 dd offset sub_A21DA0    ; DECRYPTED: HOMEDRIVE
.rdata:00AA454C                 dd offset sub_A21DC0    ; DECRYPTED: HOMEPATH
.rdata:00AA4550                 dd offset sub_A21DE0    ; DECRYPTED: Desktop\
.rdata:00AA4554                 dd offset sub_A21E00    ; DECRYPTED: Control Panel\Desktop
.rdata:00AA4558                 dd offset sub_A21E20    ; DECRYPTED: WallPaper
.rdata:00AA455C                 dd offset sub_A21E40    ; DECRYPTED: {{id}}
.rdata:00AA4560                 dd offset sub_A21E60    ; DECRYPTED: {{ext}}
.rdata:00AA4564                 dd offset sub_A21E80    ; DECRYPTED: update
.rdata:00AA4568                 dd offset sub_A21EA0    ; DECRYPTED: Global\{A86668A3-8F20-41F3-97D1-676B2AD6ADF7}
.rdata:00AA456C                 dd offset sub_A21EC0    ; DECRYPTED: \Program Files\Microsoft\Exchange Server
.rdata:00AA4570                 dd offset sub_A21EE0    ; DECRYPTED: \Program Files (x86)\Microsoft\Exchange Server
.rdata:00AA4574                 dd offset sub_A21F00    ; DECRYPTED: \Program Files\Microsoft SQL Server
.rdata:00AA4578                 dd offset sub_A21F20    ; DECRYPTED: \Program Files (x86)\Microsoft SQL Server
.rdata:00AA457C                 dd offset sub_A21F40    ; DECRYPTED: \Program Files\mysql
.rdata:00AA4580                 dd offset sub_A21F60    ; DECRYPTED: \Program Files (x86)\mysql
.rdata:00AA4584                 dd offset sub_A21F80    ; DECRYPTED: ROOT\CIMV2
.rdata:00AA4588                 dd offset sub_A21FA0    ; DECRYPTED: WQL
.rdata:00AA458C                 dd offset sub_A21FC0    ; DECRYPTED: SELECT * FROM Win32_PerfFormattedData_PerfProc_Process
.rdata:00AA4590                 dd offset sub_A21FE0    ; DECRYPTED: Name
.rdata:00AA4594                 dd offset sub_A22000    ; DECRYPTED: IDProcess
.rdata:00AA4598                 dd offset sub_A22020    ; DECRYPTED: PercentProcessorTime
.rdata:00AA459C                 dd offset sub_A22040    ; DECRYPTED: svchost
.rdata:00AA45A0                 dd offset sub_A22060    ; DECRYPTED: csrss
.rdata:00AA45A4                 dd offset sub_A22080    ; DECRYPTED: services
.rdata:00AA45A8                 dd offset sub_A220A0    ; DECRYPTED: lsass
.rdata:00AA45AC                 dd offset sub_A220C0    ; DECRYPTED: winlogon
.rdata:00AA45B0                 dd offset sub_A220E0    ; DECRYPTED: spoolsv
.rdata:00AA45B4                 dd offset sub_A22100    ; DECRYPTED: explorer
.rdata:00AA45B8                 dd offset sub_A22120    ; DECRYPTED: RuntimeBroker
.rdata:00AA45BC                 dd offset sub_A22140    ; DECRYPTED: System
.rdata:00AA45C0                 dd offset sub_A22160    ; DECRYPTED: powershell
.rdata:00AA45C4                 dd offset sub_A22180    ; DECRYPTED: wscript
.rdata:00AA45C8                 dd offset sub_A221A0    ; DECRYPTED: Create
.rdata:00AA45CC                 dd offset sub_A221C0    ; DECRYPTED: Win32_Process
.rdata:00AA45D0                 dd offset sub_A221E0    ; DECRYPTED: CommandLine
.rdata:00AA45D4                 dd offset sub_A22200    ; DECRYPTED: -safe
.rdata:00AA45D8                 dd offset sub_A22220    ; DECRYPTED: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
.rdata:00AA45DC                 dd offset sub_A22240    ; DECRYPTED: explorer.exe,
.rdata:00AA45E0                 dd offset sub_A22260    ; DECRYPTED: Shell
.rdata:00AA45E4                 dd offset sub_A22280    ; DECRYPTED: bcdedit /set safeboot network
.rdata:00AA45E8                 dd offset sub_A222A0    ; DECRYPTED: bcdedit /deletevalue safeboot
.rdata:00AA45EC                 dd offset sub_A222C0
.rdata:00AA45F0                 dd offset sub_A222E0    ; DECRYPTED: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
.rdata:00AA45F4                 dd offset sub_A22300    ; DECRYPTED: EnableLinkedConnections
.rdata:00AA45F8                 dd offset sub_A22320    ; DECRYPTED: EnableLUA
.rdata:00AA45FC                 dd offset sub_A22340    ; DECRYPTED: ConsentPromptBehaviorAdmin
.rdata:00AA4600                 dd offset sub_A22360    ; DECRYPTED: SYSTEMDRIVE
.rdata:00AA4604                 dd offset sub_A22380    ; DECRYPTED: PROGRAMFILES(x86)
.rdata:00AA4608                 dd offset sub_A223A0    ; DECRYPTED: USERPROFILE
.rdata:00AA460C                 dd offset sub_A223C0    ; DECRYPTED: ProgramData
.rdata:00AA4610                 dd offset sub_A223E0    ; DECRYPTED: Program Files
.rdata:00AA4614                 dd offset sub_A22400    ; DECRYPTED: ALLUSERSPROFILE
.rdata:00AA4618                 dd offset sub_A22420    ; DECRYPTED: AppData
.rdata:00AA461C                 dd offset sub_A22440    ; DECRYPTED: PUBLIC
.rdata:00AA4620                 dd offset sub_A22460    ; DECRYPTED: TMP
.rdata:00AA4624                 dd offset sub_A22480    ; DECRYPTED: Tor Browser
.rdata:00AA4628                 dd offset sub_A224A0    ; DECRYPTED: MSOCache
.rdata:00AA462C                 dd offset sub_A224C0    ; DECRYPTED: EFI
.rdata:00AA4630                 dd offset sub_A224E0    ; DECRYPTED: \Windows
.rdata:00AA4634                 dd offset sub_A22500    ; DECRYPTED: \Program Files
.rdata:00AA4638                 dd offset sub_A22520    ; DECRYPTED: \Users\All Users
.rdata:00AA463C                 dd offset sub_A22540    ; DECRYPTED: \AppData
.rdata:00AA4640                 dd offset sub_A22560    ; DECRYPTED: \Microsoft\Windows
.rdata:00AA4644                 dd offset sub_A22580    ; DECRYPTED: wmic SHADOWCOPY DELETE /nointeractive
.rdata:00AA4648                 dd offset sub_A225A0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP
.rdata:00AA464C                 dd offset sub_A225C0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
.rdata:00AA4650                 dd offset sub_A225E0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
.rdata:00AA4654                 dd offset sub_A22600    ; DECRYPTED: vssadmin Delete Shadows /All /Quiet
.rdata:00AA4658                 dd offset sub_A22620    ; DECRYPTED: bcdedit /set {default} recoveryenabled No
.rdata:00AA465C                 dd offset sub_A22640    ; DECRYPTED: bcdedit /set {default} bootstatuspolicy ignoreallfailures
.rdata:00AA4660                 dd offset sub_A22660    ; DECRYPTED: .vhd
.rdata:00AA4664                 dd offset sub_A22680    ; DECRYPTED: .vhdx
.rdata:00AA4668                 dd offset sub_A226A0    ; DECRYPTED: powershell Dismount-DiskImage -ImagePath
.rdata:00AA466C                 dd offset sub_A226C0    ; DECRYPTED: powershell.exe
.rdata:00AA4670                 dd offset sub_A226E0    ; DECRYPTED: _readme_.txt
.rdata:00AA4674                 dd offset sub_A22700    ; DECRYPTED: HOMEDRIVE
.rdata:00AA4678                 dd offset sub_A22720    ; DECRYPTED: HOMEPATH
.rdata:00AA467C                 dd offset sub_A22740    ; DECRYPTED: Desktop\
.rdata:00AA4680                 dd offset sub_A22760    ; DECRYPTED: Control Panel\Desktop
.rdata:00AA4684                 dd offset sub_A22780    ; DECRYPTED: WallPaper
.rdata:00AA4688                 dd offset sub_A227A0    ; DECRYPTED: {{id}}
.rdata:00AA468C                 dd offset sub_A227C0    ; DECRYPTED: {{ext}}
.rdata:00AA4690                 dd offset sub_A227E0    ; DECRYPTED: update
.rdata:00AA4694                 dd offset sub_A22800    ; DECRYPTED: Global\{A86668A3-8F20-41F3-97D1-676B2AD6ADF7}
.rdata:00AA4698                 dd offset sub_A22820    ; DECRYPTED: \Program Files\Microsoft\Exchange Server
.rdata:00AA469C                 dd offset sub_A22840    ; DECRYPTED: \Program Files (x86)\Microsoft\Exchange Server
.rdata:00AA46A0                 dd offset sub_A22860    ; DECRYPTED: \Program Files\Microsoft SQL Server
.rdata:00AA46A4                 dd offset sub_A22880    ; DECRYPTED: \Program Files (x86)\Microsoft SQL Server
.rdata:00AA46A8                 dd offset sub_A228A0    ; DECRYPTED: \Program Files\mysql
.rdata:00AA46AC                 dd offset sub_A228C0    ; DECRYPTED: \Program Files (x86)\mysql
.rdata:00AA46B0                 dd offset sub_A228E0    ; DECRYPTED: ROOT\CIMV2
.rdata:00AA46B4                 dd offset sub_A22900    ; DECRYPTED: WQL
.rdata:00AA46B8                 dd offset sub_A22920    ; DECRYPTED: SELECT * FROM Win32_PerfFormattedData_PerfProc_Process
.rdata:00AA46BC                 dd offset sub_A22940    ; DECRYPTED: Name
.rdata:00AA46C0                 dd offset sub_A22960    ; DECRYPTED: IDProcess
.rdata:00AA46C4                 dd offset sub_A22980    ; DECRYPTED: PercentProcessorTime
.rdata:00AA46C8                 dd offset sub_A229A0    ; DECRYPTED: svchost
.rdata:00AA46CC                 dd offset sub_A229C0    ; DECRYPTED: csrss
.rdata:00AA46D0                 dd offset sub_A229E0    ; DECRYPTED: services
.rdata:00AA46D4                 dd offset sub_A22A00    ; DECRYPTED: lsass
.rdata:00AA46D8                 dd offset sub_A22A20    ; DECRYPTED: winlogon
.rdata:00AA46DC                 dd offset sub_A22A40    ; DECRYPTED: spoolsv
.rdata:00AA46E0                 dd offset sub_A22A60    ; DECRYPTED: explorer
.rdata:00AA46E4                 dd offset sub_A22A80    ; DECRYPTED: RuntimeBroker
.rdata:00AA46E8                 dd offset sub_A22AA0    ; DECRYPTED: System
.rdata:00AA46EC                 dd offset sub_A22AC0    ; DECRYPTED: powershell
.rdata:00AA46F0                 dd offset sub_A22AE0    ; DECRYPTED: wscript
.rdata:00AA46F4                 dd offset sub_A22B00    ; DECRYPTED: Create
.rdata:00AA46F8                 dd offset sub_A22B20    ; DECRYPTED: Win32_Process
.rdata:00AA46FC                 dd offset sub_A22B40    ; DECRYPTED: CommandLine
.rdata:00AA4700                 dd offset sub_A22B60    ; DECRYPTED: -safe
.rdata:00AA4704                 dd offset sub_A22B80    ; DECRYPTED: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
.rdata:00AA4708                 dd offset sub_A22BA0    ; DECRYPTED: explorer.exe,
.rdata:00AA470C                 dd offset sub_A22BC0    ; DECRYPTED: Shell
.rdata:00AA4710                 dd offset sub_A22BE0    ; DECRYPTED: bcdedit /set safeboot network
.rdata:00AA4714                 dd offset sub_A22C00    ; DECRYPTED: bcdedit /deletevalue safeboot
.rdata:00AA4718                 dd offset sub_A22C20
.rdata:00AA471C                 dd offset sub_A22C40    ; DECRYPTED: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
.rdata:00AA4720                 dd offset sub_A22C60    ; DECRYPTED: EnableLinkedConnections
.rdata:00AA4724                 dd offset sub_A22C80    ; DECRYPTED: EnableLUA
.rdata:00AA4728                 dd offset sub_A22CA0    ; DECRYPTED: ConsentPromptBehaviorAdmin
.rdata:00AA472C                 dd offset sub_A22CC0    ; DECRYPTED: SYSTEMDRIVE
.rdata:00AA4730                 dd offset sub_A22CE0    ; DECRYPTED: PROGRAMFILES(x86)
.rdata:00AA4734                 dd offset sub_A22D00    ; DECRYPTED: USERPROFILE
.rdata:00AA4738                 dd offset sub_A22D20    ; DECRYPTED: ProgramData
.rdata:00AA473C                 dd offset sub_A22D40    ; DECRYPTED: Program Files
.rdata:00AA4740                 dd offset sub_A22D60    ; DECRYPTED: ALLUSERSPROFILE
.rdata:00AA4744                 dd offset sub_A22D80    ; DECRYPTED: AppData
.rdata:00AA4748                 dd offset sub_A22DA0    ; DECRYPTED: PUBLIC
.rdata:00AA474C                 dd offset sub_A22DC0    ; DECRYPTED: TMP
.rdata:00AA4750                 dd offset sub_A22DE0    ; DECRYPTED: Tor Browser
.rdata:00AA4754                 dd offset sub_A22E00    ; DECRYPTED: MSOCache
.rdata:00AA4758                 dd offset sub_A22E20    ; DECRYPTED: EFI
.rdata:00AA475C                 dd offset sub_A22E40    ; DECRYPTED: \Windows
.rdata:00AA4760                 dd offset sub_A22E60    ; DECRYPTED: \Program Files
.rdata:00AA4764                 dd offset sub_A22E80    ; DECRYPTED: \Users\All Users
.rdata:00AA4768                 dd offset sub_A22EA0    ; DECRYPTED: \AppData
.rdata:00AA476C                 dd offset sub_A22EC0    ; DECRYPTED: \Microsoft\Windows
.rdata:00AA4770                 dd offset sub_A22EE0    ; DECRYPTED: wmic SHADOWCOPY DELETE /nointeractive
.rdata:00AA4774                 dd offset sub_A22F00    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP
.rdata:00AA4778                 dd offset sub_A22F20    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
.rdata:00AA477C                 dd offset sub_A22F40    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
.rdata:00AA4780                 dd offset sub_A22F60    ; DECRYPTED: vssadmin Delete Shadows /All /Quiet
.rdata:00AA4784                 dd offset sub_A22F80    ; DECRYPTED: bcdedit /set {default} recoveryenabled No
.rdata:00AA4788                 dd offset sub_A22FA0    ; DECRYPTED: bcdedit /set {default} bootstatuspolicy ignoreallfailures
.rdata:00AA478C                 dd offset sub_A22FC0    ; DECRYPTED: .vhd
.rdata:00AA4790                 dd offset sub_A22FE0    ; DECRYPTED: .vhdx
.rdata:00AA4794                 dd offset sub_A23000    ; DECRYPTED: powershell Dismount-DiskImage -ImagePath
.rdata:00AA4798                 dd offset sub_A23020    ; DECRYPTED: powershell.exe
.rdata:00AA479C                 dd offset sub_A23040    ; DECRYPTED: _readme_.txt
.rdata:00AA47A0                 dd offset sub_A23060    ; DECRYPTED: HOMEDRIVE
.rdata:00AA47A4                 dd offset sub_A23080    ; DECRYPTED: HOMEPATH
.rdata:00AA47A8                 dd offset sub_A230A0    ; DECRYPTED: Desktop\
.rdata:00AA47AC                 dd offset sub_A230C0    ; DECRYPTED: Control Panel\Desktop
.rdata:00AA47B0                 dd offset sub_A230E0    ; DECRYPTED: WallPaper
.rdata:00AA47B4                 dd offset sub_A23100    ; DECRYPTED: {{id}}
.rdata:00AA47B8                 dd offset sub_A23120    ; DECRYPTED: {{ext}}
.rdata:00AA47BC                 dd offset sub_A23140    ; DECRYPTED: update
.rdata:00AA47C0                 dd offset sub_A23160    ; DECRYPTED: Global\{A86668A3-8F20-41F3-97D1-676B2AD6ADF7}
.rdata:00AA47C4                 dd offset sub_A23180    ; DECRYPTED: \Program Files\Microsoft\Exchange Server
.rdata:00AA47C8                 dd offset sub_A231A0    ; DECRYPTED: \Program Files (x86)\Microsoft\Exchange Server
.rdata:00AA47CC                 dd offset sub_A231C0    ; DECRYPTED: \Program Files\Microsoft SQL Server
.rdata:00AA47D0                 dd offset sub_A231E0    ; DECRYPTED: \Program Files (x86)\Microsoft SQL Server
.rdata:00AA47D4                 dd offset sub_A23200    ; DECRYPTED: \Program Files\mysql
.rdata:00AA47D8                 dd offset sub_A23220    ; DECRYPTED: \Program Files (x86)\mysql
.rdata:00AA47DC                 dd offset sub_A23240    ; DECRYPTED: ROOT\CIMV2
.rdata:00AA47E0                 dd offset sub_A23260    ; DECRYPTED: WQL
.rdata:00AA47E4                 dd offset sub_A23280    ; DECRYPTED: SELECT * FROM Win32_PerfFormattedData_PerfProc_Process
.rdata:00AA47E8                 dd offset sub_A232A0    ; DECRYPTED: Name
.rdata:00AA47EC                 dd offset sub_A232C0    ; DECRYPTED: IDProcess
.rdata:00AA47F0                 dd offset sub_A232E0    ; DECRYPTED: PercentProcessorTime
.rdata:00AA47F4                 dd offset sub_A23300    ; DECRYPTED: svchost
.rdata:00AA47F8                 dd offset sub_A23320    ; DECRYPTED: csrss
.rdata:00AA47FC                 dd offset sub_A23340    ; DECRYPTED: services
.rdata:00AA4800                 dd offset sub_A23360    ; DECRYPTED: lsass
.rdata:00AA4804                 dd offset sub_A23380    ; DECRYPTED: winlogon
.rdata:00AA4808                 dd offset sub_A233A0    ; DECRYPTED: spoolsv
.rdata:00AA480C                 dd offset sub_A233C0    ; DECRYPTED: explorer
.rdata:00AA4810                 dd offset sub_A233E0    ; DECRYPTED: RuntimeBroker
.rdata:00AA4814                 dd offset sub_A23400    ; DECRYPTED: System
.rdata:00AA4818                 dd offset sub_A23420    ; DECRYPTED: powershell
.rdata:00AA481C                 dd offset sub_A23440    ; DECRYPTED: wscript
.rdata:00AA4820                 dd offset sub_A23460    ; DECRYPTED: Create
.rdata:00AA4824                 dd offset sub_A23480    ; DECRYPTED: Win32_Process
.rdata:00AA4828                 dd offset sub_A234A0    ; DECRYPTED: CommandLine
.rdata:00AA482C                 dd offset sub_A234C0    ; DECRYPTED: -safe
.rdata:00AA4830                 dd offset sub_A234E0    ; DECRYPTED: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
.rdata:00AA4834                 dd offset sub_A23500    ; DECRYPTED: explorer.exe,
.rdata:00AA4838                 dd offset sub_A23520    ; DECRYPTED: Shell
.rdata:00AA483C                 dd offset sub_A23540    ; DECRYPTED: bcdedit /set safeboot network
.rdata:00AA4840                 dd offset sub_A23560    ; DECRYPTED: bcdedit /deletevalue safeboot
.rdata:00AA4844                 dd offset sub_A23580
.rdata:00AA4848                 dd offset sub_A235A0    ; DECRYPTED: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
.rdata:00AA484C                 dd offset sub_A235C0    ; DECRYPTED: EnableLinkedConnections
.rdata:00AA4850                 dd offset sub_A235E0    ; DECRYPTED: EnableLUA
.rdata:00AA4854                 dd offset sub_A23600    ; DECRYPTED: ConsentPromptBehaviorAdmin
.rdata:00AA4858                 dd offset sub_A23620    ; DECRYPTED: SYSTEMDRIVE
.rdata:00AA485C                 dd offset sub_A23640    ; DECRYPTED: PROGRAMFILES(x86)
.rdata:00AA4860                 dd offset sub_A23660    ; DECRYPTED: USERPROFILE
.rdata:00AA4864                 dd offset sub_A23680    ; DECRYPTED: ProgramData
.rdata:00AA4868                 dd offset sub_A236A0    ; DECRYPTED: Program Files
.rdata:00AA486C                 dd offset sub_A236C0    ; DECRYPTED: ALLUSERSPROFILE
.rdata:00AA4870                 dd offset sub_A236E0    ; DECRYPTED: AppData
.rdata:00AA4874                 dd offset sub_A23700    ; DECRYPTED: PUBLIC
.rdata:00AA4878                 dd offset sub_A23720    ; DECRYPTED: TMP
.rdata:00AA487C                 dd offset sub_A23740    ; DECRYPTED: Tor Browser
.rdata:00AA4880                 dd offset sub_A23760    ; DECRYPTED: MSOCache
.rdata:00AA4884                 dd offset sub_A23780    ; DECRYPTED: EFI
.rdata:00AA4888                 dd offset sub_A237A0    ; DECRYPTED: \Windows
.rdata:00AA488C                 dd offset sub_A237C0    ; DECRYPTED: \Program Files
.rdata:00AA4890                 dd offset sub_A237E0    ; DECRYPTED: \Users\All Users
.rdata:00AA4894                 dd offset sub_A23800    ; DECRYPTED: \AppData
.rdata:00AA4898                 dd offset sub_A23820    ; DECRYPTED: \Microsoft\Windows
.rdata:00AA489C                 dd offset sub_A23840    ; DECRYPTED: wmic SHADOWCOPY DELETE /nointeractive
.rdata:00AA48A0                 dd offset sub_A23860    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP
.rdata:00AA48A4                 dd offset sub_A23880    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
.rdata:00AA48A8                 dd offset sub_A238A0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
.rdata:00AA48AC                 dd offset sub_A238C0    ; DECRYPTED: vssadmin Delete Shadows /All /Quiet
.rdata:00AA48B0                 dd offset sub_A238E0    ; DECRYPTED: bcdedit /set {default} recoveryenabled No
.rdata:00AA48B4                 dd offset sub_A23900    ; DECRYPTED: bcdedit /set {default} bootstatuspolicy ignoreallfailures
.rdata:00AA48B8                 dd offset sub_A23920    ; DECRYPTED: .vhd
.rdata:00AA48BC                 dd offset sub_A23940    ; DECRYPTED: .vhdx
.rdata:00AA48C0                 dd offset sub_A23960    ; DECRYPTED: powershell Dismount-DiskImage -ImagePath
.rdata:00AA48C4                 dd offset sub_A23980    ; DECRYPTED: powershell.exe
.rdata:00AA48C8                 dd offset sub_A239A0    ; DECRYPTED: _readme_.txt
.rdata:00AA48CC                 dd offset sub_A239C0    ; DECRYPTED: HOMEDRIVE
.rdata:00AA48D0                 dd offset sub_A239E0    ; DECRYPTED: HOMEPATH
.rdata:00AA48D4                 dd offset sub_A23A00    ; DECRYPTED: Desktop\
.rdata:00AA48D8                 dd offset sub_A23A20    ; DECRYPTED: Control Panel\Desktop
.rdata:00AA48DC                 dd offset sub_A23A40    ; DECRYPTED: WallPaper
.rdata:00AA48E0                 dd offset sub_A23A60    ; DECRYPTED: {{id}}
.rdata:00AA48E4                 dd offset sub_A23A80    ; DECRYPTED: {{ext}}
.rdata:00AA48E8                 dd offset sub_A23AA0    ; DECRYPTED: update
.rdata:00AA48EC                 dd offset sub_A23AC0    ; DECRYPTED: Global\{A86668A3-8F20-41F3-97D1-676B2AD6ADF7}
.rdata:00AA48F0                 dd offset sub_A23AE0    ; DECRYPTED: \Program Files\Microsoft\Exchange Server
.rdata:00AA48F4                 dd offset sub_A23B00    ; DECRYPTED: \Program Files (x86)\Microsoft\Exchange Server
.rdata:00AA48F8                 dd offset sub_A23B20    ; DECRYPTED: \Program Files\Microsoft SQL Server
.rdata:00AA48FC                 dd offset sub_A23B40    ; DECRYPTED: \Program Files (x86)\Microsoft SQL Server
.rdata:00AA4900                 dd offset sub_A23B60    ; DECRYPTED: \Program Files\mysql
.rdata:00AA4904                 dd offset sub_A23B80    ; DECRYPTED: \Program Files (x86)\mysql
.rdata:00AA4908                 dd offset sub_A23BA0    ; DECRYPTED: ROOT\CIMV2
.rdata:00AA490C                 dd offset sub_A23BC0    ; DECRYPTED: WQL
.rdata:00AA4910                 dd offset sub_A23BE0    ; DECRYPTED: SELECT * FROM Win32_PerfFormattedData_PerfProc_Process
.rdata:00AA4914                 dd offset sub_A23C00    ; DECRYPTED: Name
.rdata:00AA4918                 dd offset sub_A23C20    ; DECRYPTED: IDProcess
.rdata:00AA491C                 dd offset sub_A23C40    ; DECRYPTED: PercentProcessorTime
.rdata:00AA4920                 dd offset sub_A23C60    ; DECRYPTED: svchost
.rdata:00AA4924                 dd offset sub_A23C80    ; DECRYPTED: csrss
.rdata:00AA4928                 dd offset sub_A23CA0    ; DECRYPTED: services
.rdata:00AA492C                 dd offset sub_A23CC0    ; DECRYPTED: lsass
.rdata:00AA4930                 dd offset sub_A23CE0    ; DECRYPTED: winlogon
.rdata:00AA4934                 dd offset sub_A23D00    ; DECRYPTED: spoolsv
.rdata:00AA4938                 dd offset sub_A23D20    ; DECRYPTED: explorer
.rdata:00AA493C                 dd offset sub_A23D40    ; DECRYPTED: RuntimeBroker
.rdata:00AA4940                 dd offset sub_A23D60    ; DECRYPTED: System
.rdata:00AA4944                 dd offset sub_A23D80    ; DECRYPTED: powershell
.rdata:00AA4948                 dd offset sub_A23DA0    ; DECRYPTED: wscript
.rdata:00AA494C                 dd offset sub_A23DC0    ; DECRYPTED: Create
.rdata:00AA4950                 dd offset sub_A23DE0    ; DECRYPTED: Win32_Process
.rdata:00AA4954                 dd offset sub_A23E00    ; DECRYPTED: CommandLine
.rdata:00AA4958                 dd offset sub_A23E20    ; DECRYPTED: -safe
.rdata:00AA495C                 dd offset sub_A23E40    ; DECRYPTED: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
.rdata:00AA4960                 dd offset sub_A23E60    ; DECRYPTED: explorer.exe,
.rdata:00AA4964                 dd offset sub_A23E80    ; DECRYPTED: Shell
.rdata:00AA4968                 dd offset sub_A23EA0    ; DECRYPTED: bcdedit /set safeboot network
.rdata:00AA496C                 dd offset sub_A23EC0    ; DECRYPTED: bcdedit /deletevalue safeboot
.rdata:00AA4970                 dd offset sub_A23EE0
.rdata:00AA4974                 dd offset sub_A23F00    ; DECRYPTED: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
.rdata:00AA4978                 dd offset sub_A23F20    ; DECRYPTED: EnableLinkedConnections
.rdata:00AA497C                 dd offset sub_A23F40    ; DECRYPTED: EnableLUA
.rdata:00AA4980                 dd offset sub_A23F60    ; DECRYPTED: ConsentPromptBehaviorAdmin
.rdata:00AA4984                 dd offset sub_A23F80    ; DECRYPTED: SYSTEMDRIVE
.rdata:00AA4988                 dd offset sub_A23FA0    ; DECRYPTED: PROGRAMFILES(x86)
.rdata:00AA498C                 dd offset sub_A23FC0    ; DECRYPTED: USERPROFILE
.rdata:00AA4990                 dd offset sub_A23FE0    ; DECRYPTED: ProgramData
.rdata:00AA4994                 dd offset sub_A24000    ; DECRYPTED: Program Files
.rdata:00AA4998                 dd offset sub_A24020    ; DECRYPTED: ALLUSERSPROFILE
.rdata:00AA499C                 dd offset sub_A24040    ; DECRYPTED: AppData
.rdata:00AA49A0                 dd offset sub_A24060    ; DECRYPTED: PUBLIC
.rdata:00AA49A4                 dd offset sub_A24080    ; DECRYPTED: TMP
.rdata:00AA49A8                 dd offset sub_A240A0    ; DECRYPTED: Tor Browser
.rdata:00AA49AC                 dd offset sub_A240C0    ; DECRYPTED: MSOCache
.rdata:00AA49B0                 dd offset sub_A240E0    ; DECRYPTED: EFI
.rdata:00AA49B4                 dd offset sub_A24100    ; DECRYPTED: \Windows
.rdata:00AA49B8                 dd offset sub_A24120    ; DECRYPTED: \Program Files
.rdata:00AA49BC                 dd offset sub_A24140    ; DECRYPTED: \Users\All Users
.rdata:00AA49C0                 dd offset sub_A24160    ; DECRYPTED: \AppData
.rdata:00AA49C4                 dd offset sub_A24180    ; DECRYPTED: \Microsoft\Windows
.rdata:00AA49C8                 dd offset sub_A241A0    ; DECRYPTED: wmic SHADOWCOPY DELETE /nointeractive
.rdata:00AA49CC                 dd offset sub_A241C0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP
.rdata:00AA49D0                 dd offset sub_A241E0    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
.rdata:00AA49D4                 dd offset sub_A24200    ; DECRYPTED: wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0
.rdata:00AA49D8                 dd offset sub_A24220    ; DECRYPTED: vssadmin Delete Shadows /All /Quiet
.rdata:00AA49DC                 dd offset sub_A24240    ; DECRYPTED: bcdedit /set {default} recoveryenabled No
.rdata:00AA49E0                 dd offset sub_A24260    ; DECRYPTED: bcdedit /set {default} bootstatuspolicy ignoreallfailures
.rdata:00AA49E4                 dd offset sub_A24280    ; DECRYPTED: .vhd
.rdata:00AA49E8                 dd offset sub_A242A0    ; DECRYPTED: .vhdx
.rdata:00AA49EC                 dd offset sub_A242C0    ; DECRYPTED: powershell Dismount-DiskImage -ImagePath
.rdata:00AA49F0                 dd offset sub_A242E0    ; DECRYPTED: powershell.exe
.rdata:00AA49F4                 dd offset sub_A24300    ; DECRYPTED: _readme_.txt
.rdata:00AA49F8                 dd offset sub_A24320    ; DECRYPTED: HOMEDRIVE
.rdata:00AA49FC                 dd offset sub_A24340    ; DECRYPTED: HOMEPATH
.rdata:00AA4A00                 dd offset sub_A24360    ; DECRYPTED: Desktop\
.rdata:00AA4A04                 dd offset sub_A24380    ; DECRYPTED: Control Panel\Desktop
.rdata:00AA4A08                 dd offset sub_A243A0    ; DECRYPTED: WallPaper
.rdata:00AA4A0C                 dd offset sub_A243C0    ; DECRYPTED: {{id}}
.rdata:00AA4A10                 dd offset sub_A243E0    ; DECRYPTED: {{ext}}
.rdata:00AA4A14                 dd offset sub_A24400    ; DECRYPTED: update
.rdata:00AA4A18                 dd offset sub_A24420    ; DECRYPTED: Global\{A86668A3-8F20-41F3-97D1-676B2AD6ADF7}
.rdata:00AA4A1C                 dd offset sub_A24440    ; DECRYPTED: \Program Files\Microsoft\Exchange Server
.rdata:00AA4A20                 dd offset sub_A24460    ; DECRYPTED: \Program Files (x86)\Microsoft\Exchange Server
.rdata:00AA4A24                 dd offset sub_A24480    ; DECRYPTED: \Program Files\Microsoft SQL Server
.rdata:00AA4A28                 dd offset sub_A244A0    ; DECRYPTED: \Program Files (x86)\Microsoft SQL Server
.rdata:00AA4A2C                 dd offset sub_A244C0    ; DECRYPTED: \Program Files\mysql
.rdata:00AA4A30                 dd offset sub_A244E0    ; DECRYPTED: \Program Files (x86)\mysql
.rdata:00AA4A34                 dd offset sub_A24500    ; DECRYPTED: ROOT\CIMV2
.rdata:00AA4A38                 dd offset sub_A24520    ; DECRYPTED: WQL
.rdata:00AA4A3C                 dd offset sub_A24540    ; DECRYPTED: SELECT * FROM Win32_PerfFormattedData_PerfProc_Process
.rdata:00AA4A40                 dd offset sub_A24560    ; DECRYPTED: Name
.rdata:00AA4A44                 dd offset sub_A24580    ; DECRYPTED: IDProcess
.rdata:00AA4A48                 dd offset sub_A245A0    ; DECRYPTED: PercentProcessorTime
.rdata:00AA4A4C                 dd offset sub_A245C0    ; DECRYPTED: svchost
.rdata:00AA4A50                 dd offset sub_A245E0    ; DECRYPTED: csrss
.rdata:00AA4A54                 dd offset sub_A24600    ; DECRYPTED: services
.rdata:00AA4A58                 dd offset sub_A24620    ; DECRYPTED: lsass
.rdata:00AA4A5C                 dd offset sub_A24640    ; DECRYPTED: winlogon
.rdata:00AA4A60                 dd offset sub_A24660    ; DECRYPTED: spoolsv
.rdata:00AA4A64                 dd offset sub_A24680    ; DECRYPTED: explorer
.rdata:00AA4A68                 dd offset sub_A246A0    ; DECRYPTED: RuntimeBroker
.rdata:00AA4A6C                 dd offset sub_A246C0    ; DECRYPTED: System
.rdata:00AA4A70                 dd offset sub_A246E0    ; DECRYPTED: powershell
.rdata:00AA4A74                 dd offset sub_A24700    ; DECRYPTED: wscript
.rdata:00AA4A78                 dd offset sub_A24720    ; DECRYPTED: Create
.rdata:00AA4A7C                 dd offset sub_A24740    ; DECRYPTED: Win32_Process
.rdata:00AA4A80                 dd offset sub_A24760    ; DECRYPTED: CommandLine
.rdata:00AA4A84                 dd offset sub_A24780    ; DECRYPTED: -safe
.rdata:00AA4A88                 dd offset sub_A247A0    ; DECRYPTED: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
.rdata:00AA4A8C                 dd offset sub_A247C0    ; DECRYPTED: explorer.exe,
.rdata:00AA4A90                 dd offset sub_A247E0    ; DECRYPTED: Shell
.rdata:00AA4A94                 dd offset sub_A24800    ; DECRYPTED: bcdedit /set safeboot network
```

- In this case: the start address of the first function is 0xAA4398, and the end address of the end function is 0xAA4A94.

# END
