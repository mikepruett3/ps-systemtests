function Send-GroupMembers {
    <#
    .SYNOPSIS
        Emails a Group Membership Report for an Active Directory Group
    .DESCRIPTION
        Sends a Group Membership Report for a specified Active Directory Group
    .PARAMETER Group
        The specified Active Directory Group to enumerate
    .PARAMETER Sender
        Senders Email Address.
    .PARAMETER Recipient
        The Email Address of the desired Recipient.
    .PARAMETER SMTPServer
        The specified SMTP server to use.
    .EXAMPLE
        Send-GroupMemberReport -Group "Domain Admins" -Recipient "your-email@example.org" -SMTPServer "mysmtp.example.org"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Group,
        [Parameter(Mandatory=$False,ValueFromPipeline=$True)]
        [string]
        $Sender = "PowerShell Reports <NoReply@NoDomain.org>",
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $Recipient,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string]
        $SMTPServer
    )

    begin {
        # Ping SMTPServer
        Write-Verbose "Testing connection to $SMTPServer to see if avaliable"
        if (!(Test-Connection -Count 1 -ComputerName $SMTPServer -Quiet )) {
            Write-Error "Cannot ping $SMTPServer!!!"
            Break
        }

        $Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #BFBFBF;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@
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

        Write-Verbose "Sending Report Email to $Recipient..."
        $Body = ($Result |
        Select-Object Name, @{Name="Distinguished Name"; Expression={$_.distinguishedName}} |
        Sort-Object -Property Name -Unique |
        ConvertTo-Html -As "Table" -PreContent "<h1>Group Membership Report</h1>" -Head $Header |
        Out-String)
        Send-MailMessage -From $Sender `
        -To $Recipient `
        -Subject "Group Membership Report - $Group" `
        -BodyAsHtml `
        -Body $Body `
        -SmtpServer $SMTPServer
    }

    end {
        Write-Verbose "Cleaning up used variables..."
        Remove-Variable -Name "Group" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Sender" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Recipient" -ErrorAction SilentlyContinue
        Remove-Variable -Name "SMTPServer" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Result" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Output" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Member" -ErrorAction SilentlyContinue
        Remove-Variable -Name "NewGroup" -ErrorAction SilentlyContinue
        Remove-Variable -Name "NewMember" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Temp" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Header" -ErrorAction SilentlyContinue
        Remove-Variable -Name "Body" -ErrorAction SilentlyContinue
    }
}