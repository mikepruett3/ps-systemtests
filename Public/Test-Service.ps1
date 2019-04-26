function Test-Service {
    <#
    .SYNOPSIS
       A PowerShell cmdlet to test Running services on a Server
    .DESCRIPTION
        Cmdlet checks the status of a specified service on a Server 
    .PARAMETER Server
        Test-Service -Server SERVER1
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
        Write-Verbose -Message "Pinging $Server..."
        if (!(Test-Connection -Count 1 -ComputerName $Server -Quiet )) {
            Write-Error "Cannot ping $Server!!!"
            Break
        }
        # Services Array
        $Services = @(
            "EAService"
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
        # Process Services on Server
        if (!($Connection -eq $False)) {
            Write-Verbose -Message "Processing each Service on $Server..."
            ForEach ( $Service in $Services ) {
                Write-Verbose -Message "Processing Service: $Service"
                if ( (Get-Service -ComputerName $Server -ServiceName $Service -ErrorAction SilentlyContinue).Status ) {
                    $Result | Add-Member -MemberType NoteProperty -Name ($Service) -Value (Get-Service -ComputerName $Server -ServiceName $Service -ErrorAction SilentlyContinue).Status
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
        $Service = $Null
        $Services = $Null
        $Server = $Null
        $Credentials = $Null
        $Creds = $Null
    }
}