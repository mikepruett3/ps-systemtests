function Test-Process {
    <#
    .SYNOPSIS
       A PowerShell cmdlet to test Running processes on a Server
    .DESCRIPTION
        Cmdlet checks the status of a specified process on a Server 
    .PARAMETER Server
        Test-Process -Server SERVER1 -Username MyUser
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [string]$Credentials,
        [string]$Username,
        [string]$Password
    )
    
    begin {
        # Create New Object
        $Result = New-Object System.Object
        # Ping Server
        Write-Verbose "Pinging $Server..."
        if (!(Test-Connection -Count 1 -ComputerName $Server -Quiet )) {
            Write-Error "Cannot ping $Server!!!"
            Break
        }
        # Processes Array
        $Processes = @(
            "easyaccess",                           # EasyAccess Dashboard
            "EAUpload",                             # EasyAccess Upload Manager
            "ScrptSrv",                             # Fortis Script Manager
            "FedEx.Gsm.Cafe.ApplicationEngine.Gui"  # FedEx Ship Manager
            "ReqMgr"                                # Term-Master Request Manager
        )
        # Check for Credentials, or Username & Password Variables
        if ( ($Credentials -eq "") -AND ($Username -eq "") ) {
            Write-Error -Message "No Username, Password or Credentials Given!!!"
            Break
        }
        # Check for Username & Password Variables
        if ( (!($Username -eq "")) -AND ($Password -eq "") ) {
            Write-Error -Message "No Username and/or Password Given!!!"
            Break
        }
        # If Credentials Variable is found, then convert to Username & Password Variable
        if (!($Credentials -eq "")) {
            # Get Credentials into variable
            $Creds = Get-Credential("$Credentials")
            $Username = $($Creds.Username)
            $Password = $($Creds.GetNetworkCredential().Password)
        }
    }
    
    process {
        # Adding Server Name to Results
        $Result | Add-Member -MemberType NoteProperty -Name "Server" -Value $Server
        # Establish $IPC Connection to Server
        try {
            Write-Verbose -Message "Connecting to IPC Share on $Server..."
            (net use \\$Server /USER:$Username $Password | Out-Null)
        }
        catch {
            Write-Error "Unable to establish SMB connection to IPC Share on $Server!!!"
            $Connection = $False
        }
        # Process Processes on Server
        Write-Verbose -Message "Processing each Process on $Server..."
        if (!($Connection -eq $False)) {
            ForEach ( $Process in $Processes ) {
                Write-Verbose -Message "Processing Process: $Process"
                if ( (Get-Process -ComputerName $Server -ProcessName $Process -ErrorAction SilentlyContinue).ID ) {
                    $Result | Add-Member -MemberType NoteProperty -Name $($Process) -Value $True
                } 
            }
        }
        # Disconnect $IPC Connection to Server
        try {
            Write-Verbose -Message "Removing Connection to IPC Share on $Server..."
            (net use \\$Server /DELETE | Out-Null)
        }
        catch {
            Write-Error "Unable to disconnect SMB connection to IPC Share on $Server!!!"
        }
        # Return the Results
        $Result
    }
    
    end {
        $Result = $Null
        $Process = $Null
        $Processes = $Null
        $Server = $Null
        $Credentials = $Null
        $Creds = $Null
    }
}