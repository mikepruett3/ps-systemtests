function Test-Connectivity {
    <#
    .SYNOPSIS
        A PowerShell cmdlet to test Server Connectivity
    .DESCRIPTION
        Cmdlet checks the Connectivity of a specified Server
    .PARAMETER Server
        The Server to check

        > Test-Connectivity -Server SERVER1
    #>
    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$True)]
        [string]$Server
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
        $Protocols = @{}
        $Protocols.RDP = 3389
        $Protocols.SSH = 22
        $Protocols.FTP = 21
        $Protocols.HTTP = 80
        $Protocols.HTTPS = 443
        $Protocols.HTTPALT = 8080
        $Protocols.EASWEB = 9088
    }
    
    process {
        # Starting Connectivity Tests
        Write-Verbose "Starting Connectivity Tests on $Server..."
        # Adding Server Name to Results
        Write-Verbose "Adding Hostname $Server to Results..."
        $Result | Add-Member -MemberType NoteProperty -Name "Server" -Value $Server
        # Adding IP Address of Server to new object
        Write-Verbose "Adding IP Address of $Server to Results..."
        $Result | Add-Member -MemberType NoteProperty -Name "RemoteAddress" -Value (Test-NetConnection -ComputerName $Server -WarningAction SilentlyContinue).RemoteAddress
        # Loop thru Protocol Hashtable
        ForEach ( $Protocol in $Protocols.GetEnumerator() ) {
            # Only add a Record to the Object if a Protocol was successfull
            if ( (Test-NetConnection -Port $Protocol.Value -ComputerName $Server -WarningAction SilentlyContinue).TcpTestSucceeded -eq $True ) {
                Write-Verbose "Checking if $Server Communicates on Port $($Protocol.Value)..."
                $Result | Add-Member -MemberType NoteProperty -Name $Protocol.Key -Value $True
            }
        }
        # Return the Results
        Write-Verbose "Returning Results back to the calling Process..."
        $Result
    }
    
    end {
        $Result = $Null
        $Server = $Null
    }
}
