function Get-GroupMembers {
    <#
    .SYNOPSIS
        Collect a list of active members of a specified Active Directory Group
    .DESCRIPTION
        Creates an object of active members of a specified Active Directory Group
    .PARAMETER Group
        The specified Active Directory Group to enumerate
    .EXAMPLE
        > Get-GroupMembers -Group "Domain Admins"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Group
    )

    begin {
        Write-Verbose "Testing if $Group actually exists..."
        if (!(Get-ADGroup -Identity $Group)) {
            Write-Error "Unable to find a group named $Group !!!"
            Break
        }

        $Result = @()
    }

    process {
        Write-Verbose "Collecting the Members of the AD Group - '$Group' ..."
        $Output = Get-ADGroupMember -Identity $Group

        Write-Verbose "Processing Members of the AD Group..."
        foreach ($Member in $Output) {
            if ($Member.objectClass -eq "group") {
                Remove-Variable -Name "NewGroup" -ErrorAction SilentlyContinue
                Remove-Variable -Name "NewMember" -ErrorAction SilentlyContinue
                Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
                $Temp = $Member.Name
                $NewGroup = Get-ADGroupMember -Identity $Member.DistinguishedName
                Write-Verbose "Found a Group as a Member, Collecting the Members of '$Temp' ..."
                foreach ($NewMember in $NewGroup) {
                    Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
                    $Temp = $NewMember.Name
                    Write-Verbose "Checking if Group Member '$Temp' is active/enabled..."
                    if ((Get-ADUser -Identity $NewMember.DistinguishedName).Enabled -ne $False) {
                        $Result += $NewMember
                    }
                }
            } else {
                Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
                $Temp = $Member.Name
                Write-Verbose "Checking if Group Member '$Temp' is active/enabled..."
                if ((Get-ADUser -Identity $Member.DistinguishedName).Enabled -ne $False) {
                    $Result += $Member
                }
            }
        }

        Return $Result
    }

    end {
        Write-Verbose "Cleaning up used variables..."
        Remove-Variable -Name "Group" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Result" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Output" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Member" -ErrorAction SilentlyContinue
        Remove-Variable -Name "NewGroup" -ErrorAction SilentlyContinue
        Remove-Variable -Name "NewMember" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
    }
}