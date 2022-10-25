$setHostnameDone = "C:\Temp\hostname_set.txt"
$setDomainDone = "C:\Temp\domain_set.txt"
$setIPDone = "C:\Temp\ip_set.txt"
$setRunOnceDone = "C:\Temp\run_once_set.txt"
$Passwort = ConvertTo-SecureString -String "Hallo123" -AsPlainText -Force
$IPv4Address = "192.168.178.230"
$standardGateway = "192.168.178.1"
$PraefixLaenge = "24"
$DomaenenName = "dedom01.de" 
$serverHostname = "DEDC01"


function Set-Powershell 
{
   Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value "powershell.exe"
   
}

function Set_Hostname 
{
    rename-computer -newname $serverHostname
    New-Item $setHostnameDone
    Restart-Computer
}

function Install_Domaincontroller 
{
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Confirm
    Install-ADDSForest -DomainName $DomaenenName -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText $Passwort -Force) -InstallDns
    Install-WindowsFeature RSAT-AD-PowerShell -Confirm
    New-Item $setDomainDone
    Restart-Computer
}

function ip_setter 
{
    $ifindexVal = (get-netadapter | where {$_.ifIndex -like "*"}).ifIndex 
    #disable dhcp on interface
    set-netipinterface -interfaceindex $ifindexVal -DHCP Disabled
    #set ip address and prefix length
    new-netipaddress -ipaddress $IPv4Address -prefixlength $PraefixLaenge -DefaultGateway $standardGateway -interfaceindex $ifindexVal
    New-Item $setIPDone
}

function run_once 
{
    new-itemproperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -propertytype String -value "Powershell c:\temp\deployment.ps1"
    New-Item $setRunOnceDone
}

function main 
{
    if(-not(Test-Path -Path $setRunOnceDone -PathType Leaf)) 
    {
    run_once
    }
    elseif(-not(Test-Path -Path $setIPDone -PathType Leaf)) 
    {
    ip_setter
    }
    elseif (-not(Test-Path -Path $setHostnameDone -PathType Leaf)) 
    {
    Set_Hostname
    }
    elseif(-not(Test-Path -Path $setDomainDone -PathType Leaf)) 
    {
    Install_Domaincontroller
    }
    else { Write-Host "Done!"}
}

Set-Powershell
main
