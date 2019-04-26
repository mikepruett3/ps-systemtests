function Test-SMBShares {
    <#
    .SYNOPSIS
       A PowerShell cmdlet to retrieve SMB Shares on a Server
    .DESCRIPTION
        Cmdlet retrieves a list of a SMB Shares on a Server 
    .PARAMETER Server
        Test-SMBShares -Server SERVER1 -Credentials MyUser
    .PARAMETER Credentials
        Test-SMBShares -Server SERVER1 -Credentials MyUser
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [string]$Credentials
    )
    
    begin {
        # Create New Object
        $Result = @() #New-Object System.Object
        # Get Credentials into variable
        $Creds = Get-Credential("$Credentials")
    }
    
    process {
        # Ping Server
        Write-Verbose "Pinging $Server..."
        if (Test-Connection -Count 1 -ComputerName $Server -Quiet) {
            # # Retrieve Operating System of $Server
            # try {
            #     Write-Verbose -Message "Retrieve Operating System of $Server..."
            #     $OS = $(Get-WmiObject -ComputerName $Server -Class Win32_OperatingSystem -Credential $Creds).Caption
            #     Write-Verbose -Message "Operating System of $Server = $OS..."
            # }
            # catch {
            #     Write-Error -Message "Unable to retrive Operating System Information from $Server!!!"
            # }
            # Establish CIM session with $Server
            try {
                Write-Verbose -Message "Establish CIM session with $Server..."
                $CIM = New-CimSession -Credential $Creds -ComputerName $Server -SessionOption (New-CimSessionOption -Protocol DCOM)
            }
            catch {
                Write-Error -Message"Unable to establish a CIM Session with $Server!!!"
                $CIM = $False
            }
            # Processing Shares
            if (!($CIM -eq $False)) {
                # Create Array of Shares
                try {
                    Write-Verbose -Message "Create Array of Shares found on $Server..."
                    $Shares = Get-CimInstance Win32_Share -CimSession $CIM
                }
                catch {
                    Write-Error -Message "Unable to retieve a list of Shares from $Server!!!"
                    $Shares = $False
                }
                if (!($Shares -eq $False)) {
                    # Process information for each $Share found
                    Write-Verbose -Message "Processing information for each Share found on $Server..."
                    ForEach ( $Share in $Shares ) {
                        Write-Verbose -Message "Processing Share: $($Share.Name)"
                        $Temp = New-Object System.Object
                        # Adding Server Name to Results
                        $Temp | Add-Member -MemberType NoteProperty -Name "Server" -Value $(($Share.PSComputerName).Split('.') | Select-Object -First 1)
                        $Temp | Add-Member -MemberType NoteProperty -Name "Name" -Value $($Share.Name)
                        #$Temp | Add-Member -MemberType NoteProperty -Name "Share" -Value $("\\" + $Share.PSComputerName + "\" + $Share.Name)
                        $Temp | Add-Member -MemberType NoteProperty -Name "Description" -Value $($Share.Description)
                        $Temp | Add-Member -MemberType NoteProperty -Name "Path" -Value $($Share.Path)
                        $Result += $Temp
                    }
                }
            }
            # Return the Results
            Write-Verbose -Message "Returning Results back to calling function or process..."
            $Result | Sort-Object -Property Name
        } else {
            Write-Error -Message "Unable to communicate with $Server!!!"
            # Return $False
            $Result = $False
        }
    }
    
    end {
        $Server = $Null
        $Credentials = $Null
        $Result = $Null
        $Creds = $Null
        $OS = $Null
        $CIM = $Null
        $Share = $Null
        $Shares = $Null
    }
}