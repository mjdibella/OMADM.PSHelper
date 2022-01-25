function Get-OMADMProvider {
    $EnrollmentsPath = "HKLM:\\SOFTWARE\Microsoft\Enrollments"
    $OMADMAccountsPath = "HKLM:\\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
    $Enrollments = (Get-ChildItem -Path $EnrollmentsPath -ErrorAction SilentlyContinue)
    if ($Enrollments -ne $null) {
        ForEach ($EnrollmentKey in $Enrollments) {
            $EnrollmentGUID = $EnrollmentKey.PSChildName
            $EnrollmentPath = "$EnrollmentsPath\$EnrollmentGUID"
            $Enrollment = (Get-ItemProperty -Path $EnrollmentPath)
            if ($Enrollment.ProviderId) {
                $OMADMAccountKey = "$OMADMAccountsPath\$EnrollmentGUID"
                $OMADMAddrInfoKey = "$OMADMAccountKey\Protected\AddrInfo"
                $OMADMAddrInfo = (Get-ItemProperty -Path $OMADMAddrInfoKey -ErrorAction SilentlyContinue)
                $Provider = New-Object PSObject
                $Provider | Add-member Noteproperty ProviderId $Enrollment.ProviderId
                $Provider | Add-member Noteproperty UPN $Enrollment.UPN
                $Provider | Add-member Noteproperty DiscoveryService $Enrollment.DiscoveryServiceFullURL
                $Provider | Add-member Noteproperty OMADMURL $OMADMAddrInfo.Addr
                $Provider
            }
        }
    }
}

function Get-OMADMStatus {
    param(
        [Parameter(Mandatory=$true)][string]$providerId
    )
    $EnrollmentsPath = "HKLM:\\SOFTWARE\Microsoft\Enrollments"
    $OMADMAccountsPath = "HKLM:\\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
    # find the UEM enrollment record
    $Enrollments = (Get-ChildItem -Path $EnrollmentsPath -ErrorAction SilentlyContinue)
    if ($Enrollments -ne $null) {
        ForEach ($EnrollmentKey in $Enrollments) {
            $EnrollmentGUID = $EnrollmentKey.PSChildName
            $EnrollmentPath = "$EnrollmentsPath\$EnrollmentGUID"
            $Enrollment = (Get-ItemProperty -Path $EnrollmentPath)
            if ($Enrollment.ProviderId -ne $null) {
                if ($Enrollment.ProviderId = $providerId) {
                    # found the UEM enrollment, now get the OMA-DM URL
                    write-host "Enrollment for ProviderId $providerId found with guid $EnrollmentGUID"
                    $OMADMAccountKey = "$OMADMAccountsPath\$EnrollmentGUID"
                    $OMADMAddrInfoKey = "$OMADMAccountKey\Protected\AddrInfo"
                    $OMADMAddrInfo = (Get-ItemProperty -Path $OMADMAddrInfoKey -ErrorAction SilentlyContinue)
                    if ($OMADMAddrInfo -ne $null) {
                        if ($OMADMAddrInfo.Addr -ne $null) {
                            # found the OMD-DM URL
                            write-host "Found OMA-DM URL $($OMADMAddrInfo.Addr)"
                            $OMADMAuthInfoKey = "$OMADMAccountKey\Protected\AuthInfo1"
                            $OMADMAuthInfo = (Get-ItemProperty -Path $OMADMAuthInfoKey -ErrorAction SilentlyContinue)
                            if ($OMADMAuthInfo.AuthName) {
                                $clientCert = Get-ChildItem -path cert:\LocalMachine\My | where-object {$_.subject -eq "CN=$($OMADMAuthInfo.AuthName)"}
                            } else {
                                write-warning "No OMA-DM client certificate identifier"
                            }
                            if ($clientcert) {
                                write-host "Testing OMADM endpoint using client certificate $($clientcert.subject)"
                                try {
                                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                                    Get-OMADMResponseProperties $(invoke-webrequest -uri $OMADMAddrInfo.Addr -method Head -Certificate $clientCert) $false
                                } catch {
                                    Set-OMADMRESTErrorResponse
                                }
                            } else { 
                                write-warning "OMA-DM client certificate not found in store"
                                write-host "Testing OMADM endpoint"
                                try {
                                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                                    Get-OMADMResponseProperties $(invoke-webrequest -uri $OMADMAddrInfo.Addr -method Head) $false
                                } catch {
                                    Set-OMADMRESTErrorResponse
                                }
                            }
                        } else {
                            write-warning "OMA-DM URL for $($OMADMAddrInfo.Addr) not found`n"
                        }
                    }
                    break
                }
            }
        }
    }
}

function Set-OMADMRESTErrorResponse {
    if ($_.Exception.Response) {
        Get-OMADMResponseProperties $_.Exception.Response $true
    } else {
        write-error $_
    }
    break
}

function Get-OMADMResponseProperties {
    param(
        [Parameter()][PSObject]$httpResponse,
        [Parameter()][boolean]$isErrorResponse
    )
    $OMADMResponseProperties = New-Object PSObject
    $OMADMResponseProperties | Add-member Noteproperty StatusCode $httpResponse.StatusCode
    $OMADMResponseProperties | Add-member Noteproperty StatusDescription $httpResponse.StatusDescription
    if ($isErrorResponse) {
        foreach ($header in $httpResponse.Headers) {
            $OMADMResponseProperties | Add-member Noteproperty $header $httpResponse.GetResponseHeader($header)
        }
    } else {
        foreach ($header in $httpResponse.Headers.Keys) {
            $OMADMResponseProperties | Add-member Noteproperty $header $httpResponse.Headers[$header]
        }
    }
    $OMADMResponseProperties
}

function Add-OMADMAdminPriv {
    param(
        [Parameter(Mandatory=$true)][string]$providerId
    )
    $EnrollmentsPath = "HKLM:\\SOFTWARE\Microsoft\Enrollments"
    # find the UEM enrollment record
    $Enrollments = (Get-ChildItem -Path $EnrollmentsPath -ErrorAction SilentlyContinue)
    if ($Enrollments -ne $null) {
        ForEach ($EnrollmentKey in $Enrollments) {
            $EnrollmentGUID = $EnrollmentKey.PSChildName
            $EnrollmentPath = "$EnrollmentsPath\$EnrollmentGUID"
            $Enrollment = (Get-ItemProperty -Path $EnrollmentPath)
            if ($Enrollment.ProviderId -ne $null) {
                if ($Enrollment.ProviderId = $providerId) {
                    # found the UEM enrollment!
                    $EnrollmentUserSID = $Enrollment.SID
                    Break
                }
            }
        }
    }
    if ($EnrollmentUserSID -ne $null) {
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $EnrollmentUserSID
            $Message = "$EnrollmentUserSID added to local group Administrators."
            $MsgType = "Information"
            write-host "$message`n"
        } catch {
            $Message = "An error occurred adding $EnrollmentUserSID to local group Administrators."
            $MsgType = "Error"
            write-error "$message`n"
        }        
    } else {
        $Message = "An enrollment for ProviderId $providerId was not found."
        $MsgType = "Warning"
        write-warning "$message`n"
    }
    New-EventLog -LogName "System" -Source $providerId -ErrorAction SilentlyContinue
    Write-EventLog -LogName "System" -Source $providerId -EventID 1001 -EntryType $MsgType -Message $Message -ErrorAction SilentlyContinue
}

function Remove-OMADMAdminPriv {
    param(
        [Parameter(Mandatory=$true)][string]$providerId
    )
    $EnrollmentsPath = "HKLM:\\SOFTWARE\Microsoft\Enrollments"
    # find the UEM enrollment record
    $Enrollments = (Get-ChildItem -Path $EnrollmentsPath -ErrorAction SilentlyContinue)
    if ($Enrollments -ne $null) {
        ForEach ($EnrollmentKey in $Enrollments) {
            $EnrollmentGUID = $EnrollmentKey.PSChildName
            $EnrollmentPath = "$EnrollmentsPath\$EnrollmentGUID"
            $Enrollment = (Get-ItemProperty -Path $EnrollmentPath)
            if ($Enrollment.ProviderId -ne $null) {
                if ($Enrollment.ProviderId = $providerId) {
                    # found the UEM enrollment!
                    $EnrollmentUserSID = $Enrollment.SID
                    Break
                }
            }
        }
    }
    if ($EnrollmentUserSID -ne $null) {
        try {
            Remove-LocalGroupMember -Group "Administrators" -Member $EnrollmentUserSID
            $Message = "$EnrollmentUserSID removed from local group Administrators."
            $MsgType = "Information"
            write-host "$message`n"
        } catch {
            $Message = "An error occurred removing $EnrollmentUserSID from local group Administrators."
            $MsgType = "Error"
            write-error "$message`n"
        }        
    } else {
        $Message = "An enrollment for ProviderId $providerId was not found."
        $MsgType = "Warning"
        write-warning "$message`n"
    }
    New-EventLog -LogName "System" -Source $providerId -ErrorAction SilentlyContinue
    Write-EventLog -LogName "System" -Source $providerId -EventID 1001 -EntryType $MsgType -Message $Message -ErrorAction SilentlyContinue
}

function Remove-OMADMEnrollment {
    param(
        [Parameter(Mandatory=$true)][string]$providerId
    )
    $EnrollmentsPath = "HKLM:\\SOFTWARE\Microsoft\Enrollments"
    $OMADMAccountsPath = "HKLM:\\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
    New-EventLog -LogName "System" -Source $providerId -ErrorAction SilentlyContinue
    # find the UEM enrollment record
    $Enrollments = (Get-ChildItem -Path $EnrollmentsPath -ErrorAction SilentlyContinue)
    ForEach ($EnrollmentKey in $Enrollments) {
        $EnrollmentGUID = $EnrollmentKey.PSChildName
        $EnrollmentPath = "$EnrollmentsPath\$EnrollmentGUID"
        $Enrollment = (Get-ItemProperty -Path $EnrollmentPath)
        if ($Enrollment.ProviderId -ne $null) {
            if ($Enrollment.ProviderId = $providerId) {
                # found the UEM enrollment, now get the OMA-DM URL
                $OMADMAccountKey = "$OMADMAccountsPath\$EnrollmentGUID"
                if ($OMADMAccountKey) {
                    # remove the enrollment record
                    Get-Item $EnrollmentKey | Remove-Item -Force
                    # remove the OMADM account
                    Get-Item $OMADMAccountKey | Remove-Item -Force
                    $message = "Removed enrollment for provider $providerId"
                    Write-Host $message
                    Write-EventLog -LogName "System" -Source $providerId -EventID 1001 -EntryType "Information" -Message $message
                } else {
                    $message = "Enrollment for provider $providerId has no associated OMA-DM account"
                    Write-warning $message
                    Write-EventLog -LogName "System" -Source $providerId -EventID 1001 -EntryType "Warning" -Message $message
                }
                break
            }
        }
    }
    if (-not $OMADMAccountKey) {
        $message = "No enrollment for provider $providerId found"
        Write-warning $message
        Write-EventLog -LogName "System" -Source $providerId -EventID 1001 -EntryType "Warning" -Message $message
    }
}