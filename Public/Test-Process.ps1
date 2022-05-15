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
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [string]
        $Server,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [string]
        $Credentials,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true)]
        [string[]]
        $Processes=@()
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
        #$Processes = @(
        #    "easyaccess",                           # EasyAccess Dashboard
        #    "EAUpload",                             # EasyAccess Upload Manager
        #    "ScrptSrv",                             # Fortis Script Manager
        #    "FedEx.Gsm.Cafe.ApplicationEngine.Gui"  # FedEx Ship Manager
        #    "ReqMgr"                                # Term-Master Request Manager
        #)

        # Slurp Credentials (and ask for them, if not stored)
        $Creds = Get-Credential("$Credentials")
        $Username = $Creds.GetNetworkCredential().username
        $Password = $Creds.GetNetworkCredential().password
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
        Return $Result
    }
    
    end {
        # Cleanup Variables
        Write-Verbose -Message "Cleaning up variables..."
        Remove-Variable -Name "Server" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Credentials" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Creds" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Result" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Process" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Processes" -ErrorAction SilentlyContinue
    }
}