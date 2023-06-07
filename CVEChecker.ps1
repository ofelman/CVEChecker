<#
.Name
    CVEChecker.ps1
    
.Author: Dan Felman/HP Inc
            June 7, 2023
.Synopsis
    CVEChecker lists Softpaqs with CVE vulnerability fixes

.DESCRIPTION
    Based on a platform and OS Version, CVEChecker finds 'BIOS' and 'Driver' Softpaqs that
    contain fixes to vulnerabilities, using information from CVA files

.Notes
    If running without parameters, CVEChecker will find this device's known updates required
    to fix CVE listed vulnerabilities. If -ListPrevious option is used, it will report on current and
    superseded vulnerabilities
    
    Otherwise, it will list Softpaqs with vulnerabilities based on Platform ID and OS Version

    From https://nvd.nist.gov/vuln: CVE defines a vulnerability as:
        "A weakness in the computational logic (e.g., code) found in software and hardware components that, 
        when exploited, results in a negative impact to confidentiality, integrity, or availability.

.Dependencies
    Requires HP Client Management Script Library (CMSL) on the system running the script
    HP Business class devices (as supported by HPIA and CMSL)

    Parameters
        -Platform < SysID >
        -OS < win10|win11>
        -OSVer < 1909|2004|2009|21H1|21H2|22H2 >
        -ListPrevious   -- also check and show previous Softpaqs w/vulnerabilities       
        -DebugOutput    -- [switch] add additional info to output 
        -NoDots         -- [switch] avoid output of '.' while looping (useful when redirecting output)

.Examples
    # check current device for updates that contain CVE security vulnerabilities
    CVEChecker.ps1       

    # check current device, with ALL output to file - only search current Softpaq versions
    CVEChecker.ps1 -NoDots > out.txt    

    # check for vulnerabilities in current versions of Softpaqs for the specified platform and OS version
    CVEChecker.ps1 -platform 880d -OS win10 -OSVer 21H2
    CVEChecker.ps1 880d win10 21H2                   # these 3 options are positional in this sequence

    # check specific platform, include previous Softpaqs versions
    CVEChecker.ps1 -platform 880d -OS win10 -OSVer 21H2 -ListPrevious
    CVEChecker.ps1 880d win10 21H2 -ListPrevious 

    # check current platform, check previous Softpaqs and search for Softpaqs with CVE fix
    CVEChecker.ps1 -ListPrevious 

#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)] [ValidatePattern('^[a-fA-F0-9]{4}$')]
    [string]$Platform,
    [Parameter(Position = 1)] [ValidateSet('win10', 'win11')]
    [string]$OS,
    [Parameter(Position = 2)] [ValidateSet('1909','2004','20H1','2009','20H2','21H1','21H2','22H2')]
    [string]$OSVer,
    [Parameter(Mandatory = $false)]
    [switch]$ListPrevious,
    [Parameter(Mandatory = $false)]
    [switch]$DebugOutput,
    [Parameter(Mandatory = $false)]
    [switch]$NoDots
    
) # param

$startTime = (Get-Date).DateTime

'CVEChecker -- start time: '+$startTime

#####################################################################################
# if #Platform not passed as argument, use the current device id
if ( $platform ) {
    $Script:ThisPlatformID = $platform
    Try {
        $Script:ThisPlatformName = (Get-HPDeviceDetails -Platform $Script:ThisPlatformID).name
    } Catch {
        Write-Warning 'HP CMSL is not available on this device, or device not supported'
        return 3
    }
} else {
    Try {
        $Script:ThisPlatformID = Get-HPDeviceProductID
        $Script:ThisPlatformName = Get-HPDeviceModel
    } Catch {
        Write-Warning 'HP CMSL is not available on this device, or device not supported'
        return 4
    }
} # else if ( $platform )

#####################################################################################
# if $Script:OS not passed as argument, used installed OS
if ( -not $Script:OS ) {
    if ( (Get-CimInstance Win32_OperatingSystem).BuildNumber -ge 22000 ) {
        $Script:OS = 'win11'
    } else {
        $Script:OS = 'win10'     
    } # else if ( (Get-CimInstance Win32_OperatingSystem).BuildNumber -ge 22000 )
} # if ( -not $Script:OS )

#####################################################################################
# if $Script:OSVer not passed as argument, used installed version
if ( -not $Script:OSVer ) {
    switch -Wildcard ( (Get-WmiObject win32_operatingsystem).version ) {
        '*18363' { $Script:OSVer = '1909' }
        '*19041' { $Script:OSVer = '2004' }
        '*19042' { $Script:OSVer = '2009' }
        '*19043' { $Script:OSVer = '21H1' }
        '*19044' { $Script:OSVer = '21H2' }
        '*19045' { $Script:OSVer = '22H2' }
        '*22000' { $Script:OSVer = '21H2' }
        '*22621' { $Script:OSVer = '22H2' }
    } # switch -Wildcard ( (Get-WmiObject win32_operatingsystem).version )
} # if ( -not $Script:OSVer )

<######################################################################################
    Function Get_CVEListFromCVA
        Decodes entries in Softpaq's CVA file that contain CVE entries. The informtion
        is usually listed in the [US.Enhancements] section of the CVA file
    Parm: $pCVAEnhancementsSection: Softpaq's CVA file [US.Enhancements] section
    return: list of CVE entries found in argument
#>#####################################################################################
Function Get_CVEListFromCVA {
    [CmdletBinding()] param( $pCVAEnhancementsSection, $pPrivateFixes )

    $gc_CVEList = @()
    if ( $null -ne $pCVAEnhancementsSection ) {
        foreach ( $iLine in $pCVAEnhancementsSection ) {    # check every line under [US.Enhacemenents] for CVE
            $iLine = ($iLine -split ',' ).replace('.','').Trim().split(' ') -match "(CVE-[1-2][0-9]{3}-[0-9]{3,5})"
            $gc_CVEList += $iLine
        } # foreach ( $iLine in $pCVAEnhancementsSection )
    } # if ( $null -ne $pCVAEnhancementsSection )

    if ( $null -ne $pPrivateFixes ) {
        foreach ( $iLine in $pPrivateFixes ) {    # check every line under [US.Enhacemenents] for CVE
            $iLine = ($iLine -split ',' ).replace('.','').Trim().split(' ') -match "(CVE-[1-2][0-9]{3}-[0-9]{3,5})"
            $gc_CVEList += $iLine
        } # foreach ( $iLine in $pPrivateFixes )
    } # if ( $null -ne $pPrivateFixes )

    return $gc_CVEList  # list of CVEs found listed in CVA file or $null
} # Function Get_CVEListFromCVA

<######################################################################################
    Function Check_CVE
        This function returns True if the argument matches Softpaq's CVE list  
    parm: $pCVEList          list of CVE entries
          $pCVE              CVE ID to be matched
    return: True if match is found in argument list, False if no match
#>#####################################################################################
Function Check_CVE {
    [CmdletBinding()] param( $pCVEList, $pCVE )
    $cv_matched = $false
    if (  $pCVE ) {
        foreach ( $iCVE in $pCVEList ) {
            if ( $iCVE -match $pCVE ) {
                $cv_matched = $True
                break
            }
        } # foreach ( $iCVE in $pCVEList )
    } # if (  $pCVE )
    return $cv_matched
} # Function Check_CVE

<######################################################################################
    Function Check_Previous
        traverses the supersede chain and find previous SOftpaqs with CVE entries
        Parm: $pSpqID: Softpaq ID to start the traversal, 
              $pPlatform: Platform M/B ID/SysID
              $pSuperseded_Spq: the Softpaq being superseded
        Return: List of Softpaqs containing CVE fixes, using supersede chain
                Each entry in list contains an array of information about Softpaq
#>#####################################################################################
Function Check_Previous {
    [CmdletBinding()] param( $pSpqID, $pPlatform, $pSuperseded_Spq )

    if ( $DebugOutput ) { ' > Check_Previous()' | out-Host  }

    $cp_RetEntries = @()            # initialize List of returned Softpaqs with CVE vulnerability fixes
    $cp_SupersededList = @()        # keep track of superseded Softpaqs to search for looper
    $cp_supersededSpqID = $pSuperseded_Spq
    $cp_currentSpqID = $pSpqID
    $cp_SpqMetadata = $null
    do { 
        Try {
            $Error.Clear()
            $cp_Line = (((get-pscallstack)[0].Location -split ' ')[2])+1
            $cp_SpqMetadata = Get-SoftpaqMetadata $cp_supersededSpqID -ErrorAction Stop
            if ( $cp_supersededSpqID -in $cp_SupersededList ) {
                break
            }
            $cp_SupersededList += $cp_supersededSpqID
            
            $cp_Superseded_SpqVendorVer = $cp_SpqMetadata.General.VendorVersion     # this could be '$cp_SpqMetadata.General.Version'
            if ( $DebugOutput ) { " > $($cp_currentSpqID) supersedes $($cp_supersededSpqID)/$($cp_SpqMetadata.General.Version)" | out-Host  }

            # check for this platform validation in CVA file AND that CVEs are found
            $cp_Superseded_CVEs = Get_CVEListFromCVA $cp_SpqMetadata.'US.Enhancements'._body
            if ( $DebugOutput ) { $cp_Superseded_CVEs | out-host }
            $cp_SupportedPlatforms = $cp_SpqMetadata."System Information".Values
            if ( ('0x'+$pPlatform -in $cp_SupportedPlatforms) -and $cp_Superseded_CVEs ) {
                $cp_Entry = [ordered]@{ 
                    SpqID = $cp_supersededSpqID ; 
                    SpqName = $cp_SpqMetadata.'Software Title'.US ; 
                    SpqVersion = $cp_Superseded_SpqVendorVer ;
                    CVEs = $cp_Superseded_CVEs ;
                    RelType = $cp_SpqMetadata.Private.Private_ReleaseType  }                 
                # add to returned array
                $cp_RetEntries += $cp_Entry
            } # if ( $cp_Superseded_CVEs )

            $cp_currentSpqID = $cp_supersededSpqID
            $cp_supersededSpqID = $cp_SpqMetadata.Softpaq.SupersededSoftpaqNumber   # let's get the next Softpaq in the list
        } Catch {
            return $cp_RetEntries
        } # Catch Try
    } while ( ($cp_supersededSpqID -ne 'none') -and ($cp_currentSpqID -notlike $cp_supersededSpqID) )  # do .. while

    if ( $DebugOutput ) { ' < Check_Previous()' | out-Host  } 
    return $cp_RetEntries     # return array of entries w/CVE fixes

} # Function Check_Previous

<######################################################################################
    Function Get_SoftpaqCVEs
        ...
        Parm: $pSpq: 
              $pSpqMetadata: 
              $pPlatformID: 
        Return: Hash table with info on this Softpaq and CVEs
#>####################################################################################
Function Get_SoftpaqCVEs {
    [CmdletBinding()] param( $pSpq, $pSpqMetadata, $pPlatform )

    $gs_SoftpaqHash = @{}

    $gs_SpqCVEList = Get_CVEListFromCVA $pSpqMetadata.'US.Enhancements'._body $pSpqMetadata.'Private_Fixes'._body
    $gs_SupersededSpqID = $pSpqMetadata.Softpaq.SupersededSoftpaqNumber

    $gs_prevCVEEntriesArray = Check_Previous $pSpq.ID $pPlatform $gs_SupersededSpqID
    
    if ( ($null -eq $gs_SpqCVEList) -and $gs_prevCVEEntriesArray ) { $gs_SpqCVEList = @() }

    if ( $gs_SpqCVEList -or $gs_prevCVEEntriesArray ) {
        $gs_SoftpaqHash = [ordered]@{
            PlatformID = $pPlatform ; 
            SpqID = $pSpq.id ; 
            SpqName = $pSpq.Name ;
            SpqVersion = $pSpq.Version ;
            CVEs = $gs_SpqCVEList  ;        # this is an array of objects                                         
            RelType = $pSpq.ReleaseType ;
            OS = $Script:OS ;
            OSVer = $Script:OSVer
        } 
        if ( $gs_prevCVEEntriesArray ) { 
            $gs_SoftpaqHash.PrevCVEs = $gs_prevCVEEntriesArray | sort-object @{ Expression = 'CVEs'; Ascending = $true }
        }   
    } # if ( $gs_SpqCVEList )
    
    return $gs_SoftpaqHash
} # Function Get_SoftpaqCVEs

#####################################################################################
# Start of Script
#####################################################################################

'-- Obtaining Softpaq List for: ['+$Script:ThisPlatformID+'] '+$Script:ThisPlatformName
'-- and OS/Version: '+$Script:OS+'/'+$Script:OSVer
Try {
    $Error.Clear()
    $SoftpaqList = Get-SoftpaqList -platform $Script:ThisPlatformID -os $Script:OS -OsVer $Script:OSVer -ErrorAction Stop
} Catch {
    'Get-SoftpaqList exception: line number '+((get-pscallstack)[0].Location -split " line ")[1]
    $error[0].exception          # $error[0].exception.gettype().fullname 
    return 6
}
# if -platform passed as argument, we are NOT checking 'this' device

$SoftpaqsWithCVEs = @()         # List of returned Softpaqs with CVE vulnerability fixes
$SoftpaqEntry = @{}

'-- Checking Current Softpaqs'' CVA files for matches - Please wait...' 
foreach ( $Spq in $SoftpaqList ) {

    if ( $DebugOutput ) { "-- Cataloging CVEs for Softpaq $($Spq.id)/$($Spq.version) $($Spq.name) " | out-Host } 
    if ( -not $NoDots ) { Write-Host '.' -NoNewline }

    if ( ($Spq.Category -match 'BIOS') -or ($Spq.Category -match 'driver') ) {

        $SpqCVEList = $null
        $prevCVEEntriesArray = $null

        # pull contents from softpaq's CVA file 
        Try {
            $Error.Clear()
            $SpqMetadata = Get-SoftpaqMetadata $Spq.id -ErrorAction Continue

            $SoftpaqEntry = Get_SoftpaqCVEs $Spq $SpqMetadata $Script:ThisPlatformID

            if ( $SoftpaqEntry.count -gt 0 ) { 
                $SoftpaqsWithCVEs += $SoftpaqEntry
                if ( $DebugOutput ) { 'adding ...'+$SoftpaqEntry.SpqID+' - count='+$SoftpaqsWithCVEs.count | out-host }
            } else {
                if ( $DebugOutput ) { 'No CVEs found for '+$SoftpaqEntry.SpqID | out-Host  }
            } 
        } Catch {
            $lineNum = ((get-pscallstack)[0].Location -split " line ")[1]
            if ( $DebugOutput ) { $Err = $error[0].exception }      # OPTIONAL: $error[0].exception.gettype().fullname 
            if ( $Err -match '404' ) {
                if ( $DebugOutput ) { "$($Spq.id):Get-SoftpaqMetadata exception: on line number '+$($lineNum) - missing CVA file" }
            } else {
                if ( $DebugOutput ) { "$($Spq.id): Get-SoftpaqMetadata exception: on line number '+$($lineNum)" }
            }
        } # Catch Try
        
    } # if ( ($Spq.Category -match 'BIOS') -or ($Spq.Category -match 'driver') )

} # foreach ( $Spq in $SoftpaqList )

####################################################################
# finally report what we found - NOTE: Output can be redirected
####################################################################
if ( -not $NoDots ) {' '}

'-- Platform Softpaqs containing CVE fixes' 
foreach ( $r in $SoftpaqsWithCVEs ) { # report on each Softpaq with CVE entries found
    '-- '+$r.SpqID+' - '+$r.SpqName+' ['+$r.SpqVersion+'] '+$r.CVAHWID+' ('+$r.RelType+')'+' ['+$r.CVEs +']'
    if ( $ListPrevious -and $r.PrevCVEs.CVEs ) {
        foreach ( $rCVE in $r.PrevCVEs ) {
            ' ---> '+$rCVE.SpqID+'/Older ['+$rCVE.SpqVersion+'] '+'('+$rCVE.RelType+')'+' ['+$rCVE.CVEs +']'
        } # foreach ( $rCVE in $r.PrevCVEs )
    } # if ( $r.PrevCVEs.CVEs )
} # foreach ( $r in $SoftpaqsWithCVEs )

$endTime = get-date
$elapsedTime = New-TimeSpan -Start $startTime -End $EndTime
'-- Script Executed in (min:sec) '+$elapsedTime.Minutes+':'+$elapsedTime.Seconds
