function Get-ServerList {
    <#
    .SYNOPSIS
        Pull Server Inventory from Active Directory
    .DESCRIPTION
        A Function that creates an object with all of the Servers from a Specified Domain, as well as the Operating System Version and Service Pack.
    .PARAMETER Server
        Specify the Server Name (Domain Controller) to query
    .PARAMETER Credentials
        The Credentials used to query the specified Domain Controller.
    .PARAMETER Username
        (If not profiding a PSCredential Object) The Username used to query the specified Domain Controller.
    .PARAMETER Password
        (If not profiding a PSCredential Object) The Password used to query the specified Domain Controller.
    .PARAMETER FQDN
        To retireve reults with the Fully-Qualified Domain Name for each server
    .EXAMPLE
        Get-ServerList -Server DC1corp.net -Credentials "CORP\Administrator"
        or
        Get-ServerList -Server DC1corp.net -Username "CORP\Administrator" -Password "<Password>" -FQDN
    .NOTES
        -- Made Easier with the BetterCredentials Module - https://github.com/Jaykul/BetterCredentials --
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Domain Name")]
        [string]$Domain,
        [Parameter(Mandatory=$False, HelpMessage="Set of Credentials (DOMAIN\USERNAME)")]
        [string]$Credentials,
        [Parameter(Mandatory=$False, HelpMessage="Username")]
        [string]$Username,
        [Parameter(Mandatory=$False, HelpMessage="Password")]
        [string]$Password,
        [Parameter(Mandatory=$False, HelpMessage="Results in Fully-Qualified Domain Names?")]
        [boolean]$FQDN
    )

    begin {
        # Percent Counter
        $Counter = 0
        # Create New Array
        Write-Progress -Activity "Retrieve List of Servers" -Status "Creating Arrays" -PercentComplete -1
        $Result = @()
        # Slup Credentials (and ask for them, if not stored)
        Write-Progress -Activity "Retrieve List of Servers" -Status "Processing Credentials" -PercentComplete -1
        # Check for Credentials, or Username & Password Variables
        if ( ($Credentials -eq "") -AND ($Username -eq "") ) {
            Write-Error -Message "No Username, Password or Credentials Given!!!"
            Break
        }
        if ( ($Credentials -eq "") -AND ($Password -eq "") ) {
            Write-Error -Message "No Username, Password or Credentials Given!!!"
            Break
        }
        # Check for Username & Password Variables, create a PSCredential Object... $Creds
        if ( ($Username -ne "") -AND ($Password -ne "") ) {
            $Creds = New-Object System.Management.Automation.PSCredential ($Username, $(ConvertTo-SecureString $Password -AsPlainText -Force))
        }
        # If Credentials Variable is found, then convert to Username & Password Variable
        if (!($Credentials -eq "")) {
            # Get Credentials into variable
            $Creds = Get-Credential("$Credentials")
        }
    }
    
    process {
        # Retrieving list of Name Servers from Active Directory Domain
        Write-Progress -Activity "Retrieve List of Servers" -Status "Quering Active Directory Domain for Domain Controllers" -PercentComplete -1
        try {
            Write-Verbose -Message "Retrieving list of Name Servers (DC's) from Active Directory Domain..."
            $Server = Get-DCs -Domain $Domain
            $Server = Get-Random -InputObject $Server
        }
        catch {
            Write-Error -Message "Could not retrieve a list of Name Servers from Active Directory Domain - $Domain"
            Break
        }
        # Ping Name Server
        Write-Progress -Activity "Retrieve List of Servers" -Status "Testing Domain Controller Connectivity" -PercentComplete -1
        Write-Verbose "Checking connectivity to $Server..."
        if (!( Test-NetConnection -CommonTCPPort SMB -ComputerName $Server -InformationLevel Quiet )) {
            Write-Error "Cannot communicate with $Server!!!"
            Break
        }
        # Retrieving list of Servers from Active Directory, using $Server as anchor point
        try {
            Write-Progress -Activity "Retrieve List of Servers" -Status "Retrieving list of Servers from Domain" -PercentComplete -1
            Write-Verbose -Message "Retrieving list of Servers from Active Directory, using $Server as anchor point..."
            $Servers = Get-ADComputer -Credential $Creds -Server $Server -Filter { OperatingSystem -like "*Server*"} -ErrorAction Stop #-Property Name -ErrorAction Stop
        }
        catch {
            Write-Error -Message "Could not retrieve a list of Servers in Active Directory from this server - $Server"
            Write-Error -Message "Check the details for $Creds - Username or Password maybe incorrect."
            Break
        }

        # Processing Servers
        ForEach ( $Name in $Servers ) {
            Write-Progress -Activity "Retrieve List of Servers" -Status "Checking connectivity of Server $($Name.Name)" -PercentComplete -1
            Write-Verbose "Pinging $($Name.Name), to ensure its avaliable..."
            if ( (Test-Connection -Count 1 -ComputerName $Name.Name -Quiet) ) { #-AND (Test-NetConnection -Port 3389 -ComputerName $Name.Name -InformationLevel Quiet) ) {
                
                    if ( $FQDN -eq $True ) {
                        $Temp = [PSCustomObject]@{
                            Server = $($Name.DNSHostName)
                        }
                    } else {
                        $Temp = [PSCustomObject]@{
                            Server = $($Name.Name)
                        }
                    }
                $Result += $Temp
            }
        }
        # Return the Results
        Write-Verbose -Message "Returning Results back to calling function or process..."
        Write-Progress -Activity "Retrieve List of Servers" -Status "Returning Results" -PercentComplete -1 
        $Result
    }
    
    end {
        $Server = $Null
        $Credentials = $Null
        $Result = $Null
        $Creds = $Null
        $Servers =$Null
        $Name = $Null
        $Domain = $Null
        $Temp = $Null
    }
}
