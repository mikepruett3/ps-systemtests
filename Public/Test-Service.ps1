function Test-Service {
    <#
    .SYNOPSIS
       A PowerShell cmdlet to test Running services on a Server
    .DESCRIPTION
        Cmdlet checks the status of a specified service on a Server 
    .PARAMETER Server
        Test-Service -Server DC1corp.net -Credential mycreds@example.com
    .NOTES
        -- Made Easier with the BetterCredentials Module - https://github.com/Jaykul/BetterCredentials --
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
        $Services=@()
    )
    
    begin {
        # Create New Object
        $Result = New-Object System.Object

        # Ping Server
        Write-Verbose -Message "Pinging $Server..."
        if (!(Test-Connection -Count 1 -ComputerName $Server -Quiet )) {
            Write-Error "Count not communicate with $Server"
            Break
        }

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

        # Process Services on Server
        if (!($Connection -eq $False)) {
            Write-Verbose -Message "Processing each Service on $Server..."
            ForEach ( $Service in $Services ) {
                Write-Verbose -Message "Processing Service: $Service"
                #if ( (Get-Service -ComputerName $Server -ServiceName $Service -ErrorAction SilentlyContinue).Status ) {
                    $Result | Add-Member -MemberType NoteProperty -Name ($Service) -Value (Get-Service -ComputerName $Server -ServiceName $Service -ErrorAction SilentlyContinue).Status
                #}
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
        $Result = $Null
        $Service = $Null
        $Services = $Null
        $Server = $Null
        $Credentials = $Null
        $Creds = $Null
    }
}