function Test-WebSite {
    <#
    .SYNOPSIS
        A PowerShell cmdlet to test WebSites
    .DESCRIPTION
        Cmdlet checks the connectivity, and page status of a WebSite
    .PARAMETER Site
        The WebSite to check

        > Test-WebServer -Site https://www.google.com
    #>
    [CmdletBinding()]

    param (
        # Ingest $Site variable as [URI], so much easier than -split ":"...
        [Parameter(Mandatory=$True)]
        [ValidatePattern( "^(http|https)://" )]
        [URI]$Site
    )
    
    begin {
        # Create New Object
        $Result = New-Object System.Object

        # Ping Server
        Write-Verbose "Pinging $($Site.Host)..."
        if (!(Test-Connection -Count 1 -ComputerName $Site.Host -Quiet )) {
            Write-Error "Cannot ping $($Site.Host)!!!"
            Break
        }

        # Protocol Hashtable
        $Protocols = @{}
        $Protocols.HTTP = 80
        $Protocols.HTTPS = 443
        $Protocols.8080 = 8080
    }
    
    process {
        # Create New Object
        $Result = New-Object System.Object
        # Adding Site Name to Results
        $Result | Add-Member -MemberType NoteProperty -Name "Site" -Value $Site.Host
        # Adding URL of Site to new object
        $Result | Add-Member -MemberType NoteProperty -Name "URL" -Value $Site.OriginalString
        # Loop thru Protocol Hashtable
        ForEach ( $Protocol in $Protocols.GetEnumerator() ) {
            Write-Verbose "Checking for $($Protocol.Key) connectivity on $($Site.Host)..."
            $Result | Add-Member -MemberType NoteProperty -Name $Protocol.Key -Value ( Test-NetConnection -Port $Protocol.Value -ComputerName $Site.Host ).TcpTestSucceeded
        }
        # Checking connectivity of Custom Website Port
        Write-Verbose "Checking for $($Site.Port) connectivity on $($Site.Host)..."
        if ( ! ( $Protocols.ContainsValue($Site.Port) ) ) {
            $Result | Add-Member -MemberType NoteProperty -Name $Site.Port -Value (Test-NetConnection -Port $Site.Port -ComputerName $Site.Host).TcpTestSucceeded
        }
        # Checking URL via WebRequest
        try {
            Write-Verbose "Checking Pages hosted on $($Site.AbsoluteUri)..."
            $WebRequest = Invoke-WebRequest -URI $Site.AbsoluteUri -ErrorAction SilentlyContinue
            $Result | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $WebRequest.StatusCode
            $Result | Add-Member -MemberType NoteProperty -Name "StatusDescription" -Value $WebRequest.StatusDescription
        }
        catch {
            #Write-Error "Unable to request pages from $($Site.AbsoluteUri)!!!"
            $Result | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $_.Exception.Response.StatusCode.Value__
        }
        # Return Results
        Write-Output $Result
    }
    
    end {
        Clear-Variable -Name "WebRequest" -ErrorAction SilentlyContinue
        Clear-Variable -Name "Result" -ErrorAction SilentlyContinue
        Clear-Variable -Name "Protocols" -ErrorAction SilentlyContinue
    }
}
