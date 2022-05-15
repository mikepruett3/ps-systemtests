function Get-GlobalCatalogServers {
    <#
    .SYNOPSIS
        Retrieve list of Global Catalog Servers for a specified domain
    .DESCRIPTION
        A Function that creates an object with all of the Global Catalog Servers from
        a Specified Domain, as well as the IP Address and HostName.
    .PARAMETER Domain
        Specify the Domain to query
    .EXAMPLE
        Get-GlobalCatalogServers -Domain example.com
    .NOTES
        Author: Mike Pruett
        Date: May 14th, 2022
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Domain Name",ValueFromPipeline=$true)]
        [string]
        $Domain
    )

    begin {
        # Create PSObject for $Results
        $Result = @()

        # Test Domain Connectivity
        Write-Verbose -Message "Test Connectivity to $Domain"
        if (!(Test-Connection -Count 1 -ComputerName $Domain -Quiet )) {
            Write-Error "Cannot ping $Domain!!!"
            Break
        }
    }
    
    process {
        # Retrieving list of Global Catalog Servers from Active Directory Domain
        Write-Verbose -Message "Retrieve list of Global Catalog Servers from $Domain"
        try { $GC = Resolve-DnsName -Name gc._msdcs.$Domain -QuickTimeout }
        catch {
            Write-Error -Message "Could not retrieve a list of Global Catalog Servers from $Domain!!!"
            Break
        }

        # Test-Connectivity to each Global Catalog Servers
        foreach ($Server in $GC) {
            $Temp = [PSCustomObject]@{}
            Write-Verbose -Message "Checking connectivity to Global Catalog Server - $Server"
            if (Test-Connection -Count 1 -ComputerName $Server.IPAddress -Quiet) {
                $Temp | Add-Member -MemberType NoteProperty -Name "Hostname" -Value (Resolve-DnsName -Name $Server.IPAddress -QuickTimeout -ErrorAction SilentlyContinue).NameHost
                $Temp | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $Server.IPAddress
                $Temp | Add-Member -MemberType NoteProperty -Name "Alive" -Value $True
            } else {
                $Temp | Add-Member -MemberType NoteProperty -Name "Hostname" -Value (Resolve-DnsName -Name $Server.IPAddress -QuickTimeout -ErrorAction SilentlyContinue).NameHost
                $Temp | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $Server.IPAddress
                $Temp | Add-Member -MemberType NoteProperty -Name "Alive" -Value $False
            }
            $Result += $Temp
        }

        # Return the Results
        Write-Verbose -Message "Returning Results back to calling function or process..."
        Return $Result
    }
    
    end {
        # Cleanup Variables
        Write-Verbose -Message "Cleaning up variables..."
        Remove-Variable -Name "Domain" -ErrorAction SilentlyContinue
        Remove-Variable -Name "GC" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Server" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Result" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
    }
}
