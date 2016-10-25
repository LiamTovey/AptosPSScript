#requires -Version 3.0 -Modules PSLogging
<#
    APTOS POWERSHELL FUNCTIONS
    AUTHOR: Liam Tovey

    1. APPLICATIONS
    2. ENVIRONMENT
    3. CREDENTIALS
    4. INI/INF
    5. File/Folders
    6. Services
    7. SQL
#>


#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#-----[APPLICATIONS]------------------------------------------------------------------------------------------------------------#

Function Close-Application
{
  <#
      .SYNOPSIS
      Close-Application is essentially TASKKILL

      .DESCRIPTION
      Call this function with an Executable to Kill it

      .PARAMETER AppName
      Application -AppName.

      .EXAMPLE
      Close-Application -AppName explorer.exe
      This will close explorer

      .NOTES
      V.1.0 - 19/09/2016, Initial Script, Liam Tovey
  #>
 
  Param (
    [Parameter(Mandatory,HelpMessage = 'Must give a valid apllication name to close e.g Explorer.exe')][String]$AppName
  )

  Begin {
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message "Attempting to close $AppName"
  }

  Process {
    Try 
    {
      & "$env:windir\system32\taskkill.exe" /F /IM $AppName
    }
    Catch 
    {
      Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

#-----[END]---------------------------------------------------------------------------------------------------#


#-----[ENVIRONMENT]----------------------------------------------------------------------------------------------------------#

Function Set-NewCompName
{
  <#
      .SYNOPSIS
      Describe purpose of "Set-NewCompName" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER NewCompName
      Describe parameter -NewCompName.

      .PARAMETER Credential
      Describe parameter -Credential.

      .EXAMPLE
      Set-NewCompName -NewCompName Value -Credential Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Set-NewCompName

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory,HelpMessage = 'Must enter a New Computer Name')][string] $NewCompName,
    [Parameter(Mandatory,HelpMessage = 'Must pass in domain credentials')][System.Management.Automation.Credential()][pscredential] $Credential
  
  )

  Begin {
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message (('Attempting to rename computer from {0} to {1}' -f $env:COMPUTERNAME, $NewCompName))
  }

  Process {
    Try 
    {
      Rename-Computer -NewName $NewCompName -ComputerName $env:COMPUTERNAME -DomainCredential $Credential -Force
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

Function Set-AutoLogon 
{
  <#
      .SYNOPSIS
      Auto Logon for Machine

      .DESCRIPTION
      Updates registry keys for the machine to autologon as a User (POS or Administrator etc)

      .PARAMETER
      -Domain    (Mandatory)
      -User      (Mandatory)
      -Password  (Mandatory)

      .INPUTS
   
      .OUTPUTS Log File
      Stored in the Master Install log

      .NOTES
      Version:        2.0
      Author:         Liam Tovey
      Creation Date:  10/08/2016
      Purpose/Change: 
      10/08/2016 Initial script development
      30/08/2016 Chnaged to use parameters

      .EXAMPLE            
      Set-AutoLogon -Domain Allstores -User POS -Password 1234
    
  #>

  Param (
    [Parameter(Mandatory,HelpMessage = 'Must enter a Domain Name')][string] $Domain,
    [Parameter(Mandatory,HelpMessage = 'Must enter a Valid User Name')][string] $User,
    [Parameter(Mandatory,HelpMessage = 'Must enter a Valid Password')][string] $Password
  
  )

  Begin {
    
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message ('Set-AutoLogon Setting Auto Logon to be {0}' -f $User)
  }

  Process {
    Try 
    {
      $RegKey = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        
      # Set DefaultDomainName
      Set-ItemProperty -Path $RegKey -Name DefaultDomainName -Value $Domain
      
      # Set DefaultUserName
      Set-ItemProperty -Path $RegKey -Name DefaultUserName -Value $User
      
      # Set DefaultPassword
      Set-ItemProperty -Path $RegKey -Name DefaultPassword -Value $Password

      # Set AutoAdmi
      Set-ItemProperty -Path $RegKey -Name AutoAdminLogon -Value '1'
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

#-----[END]---------------------------------------------------------------------------------------------------#





#-----[CREDENTIALS]--------------------------------------------------------------------------------------------------------#
Function Get-UserCredentials
{
  <#
      .SYNOPSIS
      Describe purpose of "Get-UserCredentials" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER User
      Describe parameter -User.

      .PARAMETER PWDFileLoc
      Describe parameter -PWDFileLoc.

      .PARAMETER KEYFileLoc
      Describe parameter -KEYFileLoc.

      .EXAMPLE
      Get-UserCredentials -User Value -PWDFileLoc Value -KEYFileLoc Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Get-UserCredentials

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory,HelpMessage = 'Must enter a User Name')][string] $User,
    [Parameter(Mandatory,HelpMessage = 'Must specify the location of the Password File')][string] $PWDFileLoc,
    [Parameter(Mandatory,HelpMessage = 'Must specify the location of the KEY File')][string] $KEYFileLoc
  
  )

  Begin {
    
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message ('Importing Credentials')
  }

  Process {
    Try 
    {
      $UserName = $User
      $PasswordFile = $PWDFileLoc
      $KeyFile = $KEYFileLoc
      $Key = Get-Content -Path $KeyFile
      $UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential `
      -ArgumentList $UserName, (Get-Content -Path $PasswordFile | ConvertTo-SecureString -Key $Key)
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

Function Create-AESKEY
{
  <#
      .SYNOPSIS
      Describe purpose of "Create-AESKEY" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER KEYFileLoc
      Describe parameter -KEYFileLoc.

      .EXAMPLE
      Create-AESKEY -KEYFileLoc Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Create-AESKEY

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory,HelpMessage = 'Must specify the location of the KEY File')][string] $KEYFileLoc  
  )

  Begin {
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message ('Create AES Key to encrypt Password File')
  }

  Process {
    Try 
    {
      $KeyFile = $KEYFileLoc
      $Key = New-Object -TypeName Byte[] -ArgumentList 16   # You can use 16, 24, or 32 for AES
      [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
      $Key | Out-File -FilePath $KeyFile
      Creating SecureString object
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

Function Create-PasswordFile
{
  <#
      .SYNOPSIS
      Describe purpose of "Create-PasswordFile" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER PWDFileLoc
      Describe parameter -PWDFileLoc.

      .PARAMETER KEYFileLoc
      Describe parameter -KEYFileLoc.

      .PARAMETER UsePassword
      Describe parameter -UsePassword.

      .EXAMPLE
      Create-PasswordFile -PWDFileLoc Value -KEYFileLoc Value -UsePassword Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Create-PasswordFile

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory,HelpMessage = 'Must specify the location of the Password File')][string] $PWDFileLoc,
    [Parameter(Mandatory,HelpMessage = 'Must specify the location of the KEY File')][string] $KEYFileLoc,
    [Parameter(Mandatory,HelpMessage = 'Must specify ta Password')][string] $UsePassword  
  )

  Begin {
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message ('Creating Password File from Key')
  }

  Process {
    Try 
    {
      $PasswordFile = $PWDFileLoc
      $KeyFile = $KEYFileLoc
      $Key = Get-Content -Path $KeyFile
      $Password = $UsePassword   | ConvertTo-SecureString -AsPlainText -Force
      $Password |
      ConvertFrom-SecureString -Key $Key |
      Out-File -FilePath $PasswordFile
      Creating PSCredential object
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}




#-----[INI/INF]------------------------------------------------------------------------------------------------------------#

Function Get-IniContent 
{  
  <#  
      .Synopsis  
      Gets the content of an INI file  
          
      .Description  
      Gets the content of an INI file and returns it as a hashtable  
          
      .Notes  
      Author        : Oliver Lipkau <oliver@lipkau.net>  
      Blog        : http://oliver.lipkau.net/blog/  
      Source        : https://github.com/lipkau/PsIni 
      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91 
      Version        : 1.0 - 2010/03/12 - Initial release  
      1.1 - 2014/12/11 - Typo (Thx SLDR) 
      Typo (Thx Dave Stiff) 
          
      #Requires -Version 2.0  
          
      .Inputs  
      System.String  
          
      .Outputs  
      System.Collections.Hashtable  
          
      .Parameter FilePath  
      Specifies the path to the input file.  
          
      .Example  
      $FileContent = Get-IniContent "C:\myinifile.ini"  
      -----------  
      Description  
      Saves the content of the c:\myinifile.ini in a hashtable called $FileContent  
      
      .Example  
      $inifilepath | $FileContent = Get-IniContent  
      -----------  
      Description  
      Gets the content of the ini file passed through the pipe into a hashtable called $FileContent  
      
      .Example  
      C:\PS>$FileContent = Get-IniContent "c:\settings.ini"  
      C:\PS>$FileContent["Section"]["Key"]  
      -----------  
      Description  
      Returns the key "Key" of the section "Section" from the C:\settings.ini file  
          
      .Link  
      Out-IniFile  
  #>  
      
  [CmdletBinding()]  
  Param(  
    [ValidateNotNullOrEmpty()]  
    [ValidateScript({
          (Test-Path $_) -and ((Get-Item $_).Extension -like '*.in*')
    })]  
    [Parameter(ValueFromPipeline,Mandatory)]  
    [string]$FilePath  
  )  
      
  Begin  
  {Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Function started"}  
          
  Process  
  {  
    Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Processing file: $FilePath"  
              
    $ini = @{}  
    switch -regex -file $FilePath  
    {  
      "^\[(.+)\]$" # Section  
      {  
        $section = $matches[1]  
        $ini[$section] = @{}  
        $CommentCount = 0  
      }  
      "^(;.*)$" # Comment  
      {  
        if (!($section))  
        {  
          $section = 'No-Section'  
          $ini[$section] = @{}  
        }  
        $value = $matches[1]  
        $CommentCount = $CommentCount + 1  
        $name = 'Comment' + $CommentCount  
        $ini[$section][$name] = $value  
      }   
      '(.+?)\s*=\s*(.*)' # Key  
      {  
        if (!($section))  
        {  
          $section = 'No-Section'  
          $ini[$section] = @{}  
        }  
        $name, $value = $matches[1..2]  
        $ini[$section][$name] = $value  
      }  
    }  
    Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"  
    Return $ini  
  }  
          
  End  
  {Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Function ended"}  
} 

Function Out-IniFile 
{  
  <#  
      .Synopsis  
      Write hash content to INI file  
          
      .Description  
      Write hash content to INI file  
          
      .Notes  
      Author        : Oliver Lipkau <oliver@lipkau.net>  
      Blog        : http://oliver.lipkau.net/blog/  
      Source        : https://github.com/lipkau/PsIni 
      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91 
      Version        : 1.0 - 2010/03/12 - Initial release  
      1.1 - 2012/04/19 - Bugfix/Added example to help (Thx Ingmar Verheij)  
      1.2 - 2014/12/11 - Improved handling for missing output file (Thx SLDR) 
          
      #Requires -Version 2.0  
          
      .Inputs  
      System.String  
      System.Collections.Hashtable  
          
      .Outputs  
      System.IO.FileSystemInfo  
          
      .Parameter Append  
      Adds the output to the end of an existing file, instead of replacing the file contents.  
          
      .Parameter InputObject  
      Specifies the Hashtable to be written to the file. Enter a variable that contains the objects or type a command or expression that gets the objects.  
  
      .Parameter FilePath  
      Specifies the path to the output file.  
       
      .Parameter Encoding  
      Specifies the type of character encoding used in the file. Valid values are "Unicode", "UTF7",  
      "UTF8", "UTF32", "ASCII", "BigEndianUnicode", "Default", and "OEM". "Unicode" is the default.  
          
      "Default" uses the encoding of the system's current ANSI code page.   
          
      "OEM" uses the current original equipment manufacturer code page identifier for the operating   
      system.  
       
      .Parameter Force  
      Allows the cmdlet to overwrite an existing read-only file. Even using the Force parameter, the cmdlet cannot override security restrictions.  
          
      .Parameter PassThru  
      Passes an object representing the location to the pipeline. By default, this cmdlet does not generate any output.  
                  
      .Example  
      Out-IniFile $IniVar "C:\myinifile.ini"  
      -----------  
      Description  
      Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini  
          
      .Example  
      $IniVar | Out-IniFile "C:\myinifile.ini" -Force  
      -----------  
      Description  
      Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and overwrites the file if it is already present  
          
      .Example  
      $file = Out-IniFile $IniVar "C:\myinifile.ini" -PassThru  
      -----------  
      Description  
      Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and saves the file into $file  
  
      .Example  
      $Category1 = @{"Key1"="Value1";"Key2"="Value2"}  
      $Category2 = @{"Key1"="Value1";"Key2"="Value2"}  
      $NewINIContent = @{"Category1"=$Category1;"Category2"=$Category2}  
      Out-IniFile -InputObject $NewINIContent -FilePath "C:\MyNewFile.INI"  
      -----------  
      Description  
      Creating a custom Hashtable and saving it to C:\MyNewFile.INI  
      .Link  
      Get-IniContent  
  #>  
      
  [CmdletBinding()]  
  Param(  
    [switch]$Append,  
          
    [ValidateSet('Unicode','UTF7','UTF8','UTF32','ASCII','BigEndianUnicode','Default','OEM')]  
    [string]$Encoding = 'Unicode',  
 
          
    [ValidateNotNullOrEmpty()]  
    [ValidatePattern('^([a-zA-Z]\:)?.+\.ini$')]  
    [Parameter(Mandatory)]  
    [string]$FilePath,  
          
    [switch]$Force,  
          
    [ValidateNotNullOrEmpty()]  
    [Parameter(ValueFromPipeline,Mandatory)]  
    [Hashtable]$InputObject,  
          
    [switch]$Passthru  
  )  
      
  Begin  
  {Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Function started"}  
          
  Process  
  {  
    Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Writing to file: $FilePath"  
          
    if ($Append) 
    {
      $outfile = Get-Item $FilePath
    }  
    else 
    {
      $outfile = New-Item -ItemType file -Path $FilePath -Force:$Force
    }  
    if (!($outfile)) 
    {
      Throw 'Could not create File'
    }  
    foreach ($i in $InputObject.keys)  
    {  
      if (!($($InputObject[$i].GetType().Name) -eq 'Hashtable'))  
      {  
        #No Sections  
        Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Writing key: $i"  
        Add-Content -Path $outfile -Value "$i=$($InputObject[$i])" -Encoding $Encoding  
      }
      else 
      {  
        #Sections  
        Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Writing Section: [$i]"  
        Add-Content -Path $outfile -Value "[$i]" -Encoding $Encoding  
        Foreach ($j in $($InputObject[$i].keys | Sort-Object))  
        {  
          if ($j -match '^Comment[\d]+') 
          {  
            Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Writing comment: $j"  
            Add-Content -Path $outfile -Value "$($InputObject[$i][$j])" -Encoding $Encoding  
          }
          else 
          {  
            Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Writing key: $j"  
            Add-Content -Path $outfile -Value "$j=$($InputObject[$i][$j])" -Encoding $Encoding  
          }
        }  
        Add-Content -Path $outfile -Value '' -Encoding $Encoding  
      }  
    }  
    Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Finished Writing to file: $path"  
    if ($Passthru) 
    {
      Return $outfile
    }  
  }  
          
  End  
  {Write-Verbose -Message "$($MyInvocation.MyCommand.Name):: Function ended"}  
} 

#-----[END]---------------------------------------------------------------------------------------------------#


#-----[File/Folders]------------------------------------------------------------------------------------------------------------#



#-----[END]---------------------------------------------------------------------------------------------------#



#-----[Services]----------------------------------------------------------------------------------------------------------------#


Function Set-BTEServicesStart
{
  <#
      .DESCRIPTION
      Add a more complete description of what the function does.
  #>


  Start-Service -Name 'BTE.CardAdapter.ServiceHost'
                 
  #Start-Service -Name ''
        
  #Start-Service -Name ''
         
  #Start-Service -Name ''
}


Function Set-BTEServicesStop
{
  <#
      .DESCRIPTION
      Add a more complete description of what the function does.
  #>


  Stop-Service -Name 'BTE.CardAdapter.ServiceHost' -Force
  
  #Stop-Service -Name '' -Force
  
  #Stop-Service -Name '' -Force

  #Stop-Service -Name '' -Force
}


Function Set-BTEServices
{
  <#
      .SYNOPSIS
      Set BTE Store Services

      .DESCRIPTION
      Can Start / Stop BTE services and set startup type

      .PARAMETER
      -Service Start / Stop
      -Startup Automatic / Disabled (Optional)

      .INPUTS
      N/A

      .OUTPUTS Log File
      Stored in the Master Install log

      .NOTES
      Version:        2.0
      Author:         Liam Tovey
      Creation Date:  01/09/2016
      Purpose/Change: Initial script development

      .EXAMPLE           
      Set-BTEServices -Service Stop
      Set-BTEServices -Service Start 
      Set-BTEServices -Service Stop -Startup Disabled
  #>
  Param (
    [Parameter(Mandatory,HelpMessage = 'Enter either Start or Stop')][string] $Service,
    [String] $Startup
  )


  Begin {
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message ("Set BTE Services to $Service")
  }

  Process {
    Try 
    {
      if ($Service -eq 'Start')
      {
        Set-BTEServicesStart
      }
      Elseif ($Service -eq 'Stop')
      {
        Set-BTEServicesStop
      }
      
      if ($Startup -eq 'Automatic')
      {
        Set-Service -Name 'BTE.CardAdapter.ServiceHost' -StartupType Automatic
                 
        #Set-Service -Name '' -StartupType Automatic
        
        #Set-Service -Name '' -StartupType Automatic
         
        #Set-Service -Name '' -StartupType Automatic
        
        Set-BTEServicesStart
      }
      Elseif ($Startup -eq 'Disabled')
      {
        Set-Service -Name 'BTE.CardAdapter.ServiceHost' -StartupType Disabled
  
        #Set-Service -Name '' -StartupType Disabled
  
        #Set-Service -Name '' -StartupType Disabled

        #Set-Service -Name '' -StartupType Disabled
      }
    }     

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}



Function Set-NSBServicesStart
{
  <#
      .DESCRIPTION
      Add a more complete description of what the function does.
  #>


  Start-Service -Name 'NSB POS Service'
                 
  Start-Service -Name 'NSB Local Queue Manager'
        
  Start-Service -Name 'NSB File Distribution Manager'
         
  Start-Service -Name 'NSB Data Replication Manager'
}


Function Set-NSBServicesStop
{
  <#
      .DESCRIPTION
      Add a more complete description of what the function does.
  #>


  Stop-Service -Name 'NSB POS Service' -Force
  
  Stop-Service -Name 'NSB Local Queue Manager' -Force
  
  Stop-Service -Name 'NSB File Distribution Manager' -Force

  Stop-Service -Name 'NSB Data Replication Manager' -Force
}


Function Set-NSBServices
{
  <#
      .SYNOPSIS
      Set NSB Store Services

      .DESCRIPTION
      Can Start / Stop NSB services and set startup type

      .PARAMETER
      -Service Start / Stop
      -Startup Automatic / Disabled (Optional)

      .INPUTS
      N/A

      .OUTPUTS Log File
      Stored in the Master Install log

      .NOTES
      Version:        2.0
      Author:         Liam Tovey
      Creation Date:  01/09/2016
      Purpose/Change: Initial script development

      .EXAMPLE           
      Set-NSBServices -Service Stop
      Set-NSBServices -Service Start 
      Set-NSBServices -Service Stop -Startup Disabled
  #>

  Param (
    [Parameter(Mandatory,HelpMessage = 'Enter either Start or Stop')][string] $Service,
    [String] $Startup
  )


  Begin {
    
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message ("Set NSB Services to $Service")
  }

  Process {
    Try 
    {
      if ($Service -eq 'Start')
      {
        Set-NSBServicesStart
      }
      Elseif ($Service -eq 'Stop')
      {
        Set-NSBServicesStop
      }
      
      if ($Startup -eq 'Automatic')
      {
        Set-Service -Name 'NSB POS Service' -StartupType Automatic
                 
        Set-Service -Name 'NSB Local Queue Manager' -StartupType Automatic
        
        Set-Service -Name 'NSB File Distribution Manager' -StartupType Automatic
         
        Set-Service -Name 'NSB Data Replication Manager' -StartupType Automatic
        
        Set-NSBServicesStart
      }
      Elseif ($Startup -eq 'Disabled')
      {
        Set-Service -Name 'NSB POS Service' -StartupType Disabled
  
        Set-Service -Name 'NSB Local Queue Manager' -StartupType Disabled
  
        Set-Service -Name 'NSB File Distribution Manager' -StartupType Disabled

        Set-Service -Name 'NSB Data Replication Manager' -StartupType Disabled
      }
    }     

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}


#-----[END]---------------------------------------------------------------------------------------------------#



#-----[SQL]---------------------------------------------------------------------------------------------------------------------#

Function Start-SQLImportSQLFile
{
  <#
      .SYNOPSIS
      Describe purpose of "Start-SQLDropDatabases" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER SAPASS
      Describe parameter -SAPASS.

      .PARAMETER SQLFILE
      Describe parameter -SQLFILE.

      .PARAMETER RESULTFILE
      Describe parameter -RESULTFILE.

      .EXAMPLE
      Start-SQLDropDatabases -SAPASS Value -SQLFILE Value -RESULTFILE Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Start-SQLDropDatabases

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory)][string] $SQLUSER,
    [Parameter(Mandatory)][string] $SAPASS,
    [Parameter(Mandatory)][string] $SQLFILE,
    [string] $RESULTFILE
  )

  Begin {
  
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message "Importing SQL File $SQLFILE"
  }

  Process {
    Try 
    {
      $command = (@'
SQLCMD.EXE -U {0} -P {1} -i {2} -o {3}
'@ -f $SQLUSER, $SAPASS, $SQLFILE, $RESULTFILE)
      Invoke-Expression -Command:$command
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

Function Start-SQLMakeAttachDB 
{
  <#
      .SYNOPSIS
      Describe purpose of "Start-SQLMakeAttachDBquery" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER SQLUSER
      Describe parameter -SQLUSER.

      .PARAMETER SAPASS
      Describe parameter -SAPASS.

      .PARAMETER SQLFILE
      Describe parameter -SQLFILE.

      .PARAMETER RESULTFILE
      Describe parameter -RESULTFILE.

      .EXAMPLE
      Start-SQLMakeAttachDBquery -SQLUSER Value -SAPASS Value -SQLFILE Value -RESULTFILE Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Start-SQLMakeAttachDBquery

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory)][string] $SQLUSER,
    [Parameter(Mandatory)][string] $SAPASS,
    [Parameter(Mandatory)][string] $SQLFILE,
    [string] $RESULTFILE
  )

  Begin {
    
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Build or Import attach DB query'
  }

  Process {
    Try 
    {
      $command = (@'
SQLCMD.EXE -U {0} -P {1} -i {2} -m 1 -h-1 -o {3}
'@ -f $SQLUSER, $SAPASS, $SQLFILE, $RESULTFILE)
      Invoke-Expression -Command:$command
    }

    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

Function Start-SQLUpgrade 
{
  <#
      .SYNOPSIS
      Describe purpose of "Start-SQLUpgrade" in 1-2 sentences.

      .DESCRIPTION
      Add a more complete description of what the function does.

      .PARAMETER SQLInstaller
      Describe parameter -SQLInstaller.

      .PARAMETER INSTANCEID
      Describe parameter -INSTANCEID.

      .PARAMETER INSTANCENAME
      Describe parameter -INSTANCENAME.

      .EXAMPLE
      Start-SQLUpgrade -SQLInstaller Value -INSTANCEID Value -INSTANCENAME Value
      Describe what this call does

      .NOTES
      Place additional notes here.

      .LINK
      URLs to related sites
      The first link is opened by Get-Help -Online Start-SQLUpgrade

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      List of output types produced by this function.
  #>


  Param (
    [Parameter(Mandatory,HelpMessage = 'Specify SQL Setup Location Path e.g. C:\FBATemp\SQLEXPR2014_x86_ENU\Setup.exe')][String]$SQLInstaller,
    [String]$INSTANCEID = 'MSSQLSERVER',
    [String]$INSTANCENAME = 'MSSQLSERVER'
  )

  Begin {
  
    Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Upgrading SQL Express $SQLInstaller, $INSTANCEID, $INSTANCENAME'
  }

  Process {
    Try 
    {
      $command = (@'
cmd.exe /C start /wait {0} /QS /ACTION=upgrade /INSTANCEID={1} /INSTANCENAME={2} /ISSVCAccount="NT Authority\Network Service" /IACCEPTSQLSERVERLICENSETERMS
'@ -f $SQLInstaller, $INSTANCEID, $INSTANCENAME)
      Invoke-Expression -Command:$command
    }
    Catch 
    {
      Write-LogError -LogPath $sLogFile -TimeStamp $True -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) 
    {
      Write-LogInfo -LogPath $sLogFile -TimeStamp $True -Message 'Completed Successfully.'
      Write-LogInfo -LogPath $sLogFile -Message ' '
    }
  }
}

#-----[END]---------------------------------------------------------------------------------------------------#
#New-ModuleManifest -Path D:\Scripting\PowerShell\Modules\Aptos-PSFunctions\Aptos-PSFunctions.psd1 -PassThru -Author 'Liam Tovey' -CompanyName APTOS -CompatiblePSEditions Desktop -Copyright 'APTOS 2016' -ModuleVersion '1.0' -PowerShellVersion '4'