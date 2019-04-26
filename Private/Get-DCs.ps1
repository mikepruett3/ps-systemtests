function Get-DCs {
    <#
    .SYNOPSIS
        Retrieve List of Domain Controllers for a specified Domain
    .DESCRIPTION
        A Function that creates an array with all of the Domain Controller Servers from a Specified Domain.
    .PARAMETER Domain
        Specify the Domain Name (Fully-Qualified) to query
    .EXAMPLE
        Get-DCs -Domain contoso.com
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$Domain
    )

    begin {
        # Create New Arrays
        $Result = @()
        $NameServers = @()
    }
    
    process {
        # Retrieving list of Name Servers from Active Directory Domain
        try {
            Write-Verbose -Message "Retrieving list of Name Servers from Active Directory Domain, $Domain..."
            $NameServers = $( Resolve-DNSName -Name $Domain -Type NS -ErrorAction Stop | Select-Object NameHost | Where-Object { $_.NameHost -match ".." } )
        }
        catch {
            Write-Error -Message "Could not retrieve a list of Name Servers from this Active Directory Domain - $Domain"
            Break
        }

        # Test Connection to each NameServer
        foreach ($Server in $NameServers) {
            Write-Verbose -Message "Pinging $($Server.NameHost)..."
            if (!(Test-Connection -Count 1 -ComputerName $Server.NameHost -Quiet)) {
                Write-Error -Message "Cannot ping $($Server.NameHost)!!!"
                Continue
            } else {
                Write-Verbose -Message "Adding $($Server.NameHost) to array..."
                $Result += $($Server.NameHost)
                Continue
            }
        }
        # Return Results
        Write-Output $Result
    }
    
    end {
        Clear-Variable -Name "Domain" -ErrorAction SilentlyContinue
        Clear-Variable -Name "Result" -ErrorAction SilentlyContinue
        Clear-Variable -Name "NameServers" -ErrorAction SilentlyContinue
        Clear-Variable -Name "Server" -ErrorAction SilentlyContinue
    }
}
