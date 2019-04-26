# # Check for WebAdminisration Module
# If ( !(Get-Module -Name WebAdministration) ) {
#     Write-Host -ForegroundColor Magenta "WebAdministration Module not loaded!"
#     Break
# }
# # Check for IISAdministration Module
# If (Get-Module -Name IISAdministration) {
#     Write-Host -ForegroundColor Red "These cmdlets were designed for the WebAdministration Module only! Will not work with newer IISAdministration Module."
# }

#Get public and private function definition files. Thanks RamblingCookieMonster
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

#Dot source the files
Foreach ($import in @($Public + $Private)) {
    Try {
        Import-Module $import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename