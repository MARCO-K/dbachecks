$filename = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
. $PSScriptRoot/../internal/assertions/Instance.Assertions.ps1

[string[]]$NotContactable = (Get-PSFConfig -Module dbachecks -Name global.notcontactable).Value

# Get all the tags in use in this run 
$Tags = Get-CheckInformation -Check $Check -Group Instance -AllChecks $AllChecks -ExcludeCheck $ChecksToExclude

@(Get-Instance).ForEach{
    if ($NotContactable -notcontains $psitem) {
        $Instance = $psitem
        try {
            $InstanceSMO = Connect-DbaInstance	-SqlInstance $Instance -ErrorAction SilentlyContinue -ErrorVariable errorvar
        }
        catch {
            $NotContactable += $Instance
            $There = $false
        }
        if ($NotContactable -notcontains $psitem) {
            if ($null -eq $InstanceSMO.version) {
                $NotContactable += $Instance
                $There = $false
            }
            else {
                $There = $True
            }
        }
    }
    else {
        $There = $false
    }
    # Get the relevant information for the checks in one go to save repeated trips to the instance
    $AllInstanceInfo = Get-AllInstanceInfo -Instance $InstanceSMO -Tags $Tags -There $There
    Describe "Instance Connection" -Tags InstanceConnection, Connectivity, High, $filename {
        $skipremote = Get-DbcConfigValue skip.connection.remoting
        $skipping = Get-DbcConfigValue skip.connection.ping
        $skipauth = Get-DbcConfigValue skip.connection.auth
        $authscheme = Get-DbcConfigValue policy.connection.authscheme
        if ($NotContactable -contains $psitem) {
            Context "Testing Instance Connection on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Instance Connection on $psitem" {
                It "connects successfully to $psitem" {
                    #Because Test-DbaInstance only shows connectsuccess false if the Connect-SQlInstance throws an error and we use Connect-DbaInstance
                    $true| Should -BeTrue
                }
                #local is always NTLM except when its a container ;-)
                if ($InstanceSMO.NetBiosName -eq $ENV:COMPUTERNAME -and ($instance -notlike '*,*')) {
                    It -Skip:$skipauth "auth scheme should be NTLM on the local machine on $psitem" {
                        (Test-DbaConnectionAuthScheme -SqlInstance $Instance).authscheme| Should -Be NTLM
                    }
                }
                else {
                    It -Skip:$skipauth "auth scheme should be $authscheme on $psitem" {
                        (Test-DbaConnectionAuthScheme -SqlInstance $Instance).authscheme | Should -Be $authscheme
                    }
                }
                It -Skip:$skipping "$psitem is pingable" {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $timeout = 1000 #milliseconds
                    $reply = $ping.Send($InstanceSMO.ComputerName, $timeout)
                    $pingable = $reply.Status -eq 'Success'
                    $pingable | Should -BeTrue

                }
                It -Skip:$skipremote "$psitem Is PSRemoteable" {
                    #simple remoting check
                    try {
                        $null = Invoke-Command -ComputerName $InstanceSMO.ComputerName -ScriptBlock { Get-ChildItem } -ErrorAction Stop
                        $remoting = $true
                    }
                    catch {
                        $remoting = $false
                    }
                    $remoting | Should -BeTrue
                }
            }
        }
    }

    Describe "SQL Engine Service" -Tags SqlEngineServiceAccount, ServiceAccount, High, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Testing SQL Engine Service on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            $IsClustered = $Psitem.$IsClustered
            Context "Testing SQL Engine Service on $psitem" {
                if ( -not $IsLInux) {
                    @(Get-DbaService -ComputerName $psitem -Type Engine -ErrorAction SilentlyContinue).ForEach{
                        It "SQL Engine service account should Be running on $($psitem.InstanceName)" {
                            $psitem.State | Should -Be "Running" -Because 'If the service is not running, the SQL Server will not be accessible'
                        }
                        if ($IsClustered) {
                            It "SQL Engine service account should have a start mode of Manual on FailOver Clustered Instance $($psitem.InstanceName)" {
                                $psitem.StartMode | Should -Be "Manual" -Because 'Clustered Instances required that the SQL engine service is set to manual'
                            }
                        }
                        else {
                            It "SQL Engine service account should have a start mode of Automatic on standalone instance $($psitem.InstanceName)" {
                                $psitem.StartMode | Should -Be "Automatic" -Because 'If the server restarts, the SQL Server will not be accessible'
                            }
                        }
                    }
                }
                else {
                    It "Running on Linux so can't check Services on $Psitem" -skip {
                    }
                }
            }
        }
    }

    Describe "TempDB Configuration" -Tags TempDbConfiguration, Medium, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Testing TempDB Configuration on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing TempDB Configuration on $psitem" {
                $TempDBTest = Test-DbaTempdbConfig -SqlInstance $psitem
                 It "should have $($TempDBTest[1].Recommended) TempDB Files on $($TempDBTest[1].SqlInstance)" -Skip:(Get-DbcConfigValue skip.tempdbfileCount) {
                    $TempDBTest[1].CurrentSetting | Should -Be $TempDBTest[1].Recommended -Because 'This is the recommended number of tempdb files for your server'
                }
                It "should not have TempDB Files autogrowth set to percent on $($TempDBTest[2].SqlInstance)" -Skip:(Get-DbcConfigValue skip.TempDbFileGrowthPercent) {
                    $TempDBTest[2].CurrentSetting | Should -Be $TempDBTest[2].Recommended -Because 'Auto growth type should not be percent'
                }
                It "should not have TempDB Files on the C Drive on $($TempDBTest[3].SqlInstance)" -Skip:(Get-DbcConfigValue skip.TempDbFilesonC) {
                    $TempDBTest[3].CurrentSetting | Should -Be $TempDBTest[3].Recommended -Because 'You do not want the tempdb files on the same drive as the operating system'
                }
                It "should not have TempDB Files with MaxSize Set on $($TempDBTest[4].SqlInstance)" -Skip:(Get-DbcConfigValue skip.TempDbFileSizeMax) {
                    $TempDBTest[4].CurrentSetting | Should -Be $TempDBTest[4].Recommended -Because 'Tempdb files should be able to grow'
                }
                It "The data files should all be the same size on $($TempDBTest[0].SqlInstance)" {
                    Assert-TempDBSize -Instance $Psitem
                }
            }
        }
    }

    Describe "Ad Hoc Workload Optimization" -Tags AdHocWorkload, Medium, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Testing Ad Hoc Workload Optimization on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Ad Hoc Workload Optimization on $psitem" {
                It "$psitem Should be Optimize for Ad Hoc workloads" -Skip:((Get-Version -SQLInstance $psitem) -lt 10) {
                    @(Test-DbaOptimizeForAdHoc -SqlInstance $psitem).ForEach{
                        $psitem.CurrentOptimizeAdHoc | Should -Be $psitem.RecommendedOptimizeAdHoc -Because "optimize for ad hoc workloads is a recommended setting"
                    }
                }
            }
        }
    }

    Describe "Dedicated Administrator Connection" -Tags DAC, CIS, Low, $filename {
        $dac = Get-DbcConfigValue policy.dacallowed
        if ($NotContactable -contains $psitem) {
            Context "Testing Dedicated Administrator Connection on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Dedicated Administrator Connection on $psitem" {
                It "DAC is set to $dac on $psitem" {
                    (Get-DbaSpConfigure -SqlInstance $psitem -ConfigName 'RemoteDACConnectionsEnabled').ConfiguredValue -eq 1 | Should -Be $dac -Because 'This is the setting that you have chosen for DAC connections'
                }
            }
        }
    }

    Describe "Linked Servers" -Tags LinkedServerConnection, Connectivity, Medium, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Testing Linked Servers on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Linked Servers on $psitem" {
                @(Test-DbaLinkedServerConnection -SqlInstance $psitem).ForEach{
                    It "Linked Server $($psitem.LinkedServerName) on on $($psitem.SqlInstance) has connectivity" {
                        $psitem.Connectivity | Should -BeTrue -Because 'You need to be able to connect to your linked servers'
                    }
                }
            }
        }
    }

    Describe "Max Memory" -Tags MaxMemory, High, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Testing Max Memory on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Max Memory on $psitem" {
                if (-not $IsLInux) {
                    It "Max Memory setting should be correct on $psitem" {
                        @(Test-DbaMaxMemory -SqlInstance $psitem).ForEach{
                            $psitem.SqlMaxMB | Should -BeLessThan ($psitem.RecommendedMB + 379) -Because 'You do not want to exhaust server memory'
                        }
                    }
                }
                else {
                    It "Max Memory setting should be correct (running on Linux so only checking Max Memory is less than Total Memory) on $psitem" {
                        # simply check that the max memory is less than total memory
                        $MemoryValues = Get-DbaMaxMemory -SqlInstance $psitem
                        $MemoryValues.Total | Should -BeGreaterThan $MemoryValues.MaxValue -Because 'You do not want to exhaust server memory'
                    }
                }
            }
        }
    }

    Describe "Orphaned Files" -Tags OrphanedFile, Low, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Checking for orphaned database files on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Checking for orphaned database files on $psitem" {
                It "$psitem doesn't have orphan files" {
                    @(Find-DbaOrphanedFile -SqlInstance $psitem).Count | Should -Be 0 -Because 'You dont want any orphaned files - Use Find-DbaOrphanedFile to locate them'
                }
            }
        }
    }

    Describe "SQL and Windows names match" -Tags ServerNameMatch, Medium, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Testing instance name matches Windows name for $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing instance name matches Windows name for $psitem" {
                if ($InstanceSMO.NetBiosName -eq $ENV:COMPUTERNAME -and ($instance -like '*,*')) {
                    It "$psitem doesn't require rename as it appears to be a local container" -Skip {
                    }
                }
                else {
                    It "$psitem doesn't require rename" {
                        (Test-DbaInstanceName -SqlInstance $psitem).RenameRequired | Should -BeFalse -Because 'SQL and Windows should agree on the server name'
                    }
                }
            }
        }
    }

    Describe "SQL Memory Dumps" -Tags MemoryDump, Medium, $filename {
        $maxdumps = Get-DbcConfigValue	policy.dump.maxcount
        if ($NotContactable -contains $psitem) {
            Context "Checking that dumps on $psitem do not exceed $maxdumps for $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Checking that dumps on $psitem do not exceed $maxdumps for $psitem" {
                It "dump count of $count is less than or equal to the $maxdumps dumps on $psitem" -Skip:($InstanceSMO.Version.Major -lt 10 ) {
                    Assert-MaxDump -AllInstanceInfo $AllInstanceInfo -maxdumps $maxdumps
                }
            }
        }
    }

    Describe "Supported Build" -Tags SupportedBuild, DISA, High, $filename {
        $BuildWarning = Get-DbcConfigValue policy.build.warningwindow
        $BuildBehind = Get-DbcConfigValue policy.build.behind
        $Date = Get-Date


        if ($NotContactable -contains $psitem) {
            Context "Checking that build is still supportedby Microsoft for $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Checking that build is still supportedby Microsoft for $psitem" {
                if ($BuildBehind) {
                    It "$psitem is not behind the latest build by more than $BuildBehind" {
                        Assert-InstanceSupportedBuild -Instance $psitem -BuildBehind $BuildBehind -Date $Date
                    }
                }
                It "$Instance's build is supported by Microsoft" {
                    Assert-InstanceSupportedBuild -Instance $psitem -Date $Date
                }
                It "$Instance's build is supported by Microsoft within the warning window of $BuildWarning months" {
                    Assert-InstanceSupportedBuild -Instance $psitem -BuildWarning $BuildWarning -Date $Date
                }


            }
        }
    }

    Describe "SA login disable" -Tags SaDisabled, DISA, CIS, Medium, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Checking that sa login has been renamed on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
			Context "Checking that sa login has been disabled on $psitem" {
				$results = (Get-DbaLogin -SqlInstance $psitem -Login sa).IsDisabled
				It "sa login has been disabled on $psitem" {
					$results | Should -Be $true -Because 'Disabling the sa account is a requirement'
				}
			}
        }
    }
	
	Describe "BUILTIN\Administrators removed" -Tags BuildInAdmins, DISA, CIS, Medium, $filename {
        if ($NotContactable -contains $psitem) {
            Context "Checking that BUILTIN\Administrators login has been removed on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
			Context "Checking that BUILTIN\Administrators login has been removed on $psitem" {
				$results = (Get-DbaLogin -SqlInstance $psitem -Login 'BUILTIN\Administrators')
				It "BUILTIN\Administrators login does not exist on $psitem" {
					$results | Should -Be $null -Because 'Removing the BUILTIN\Administrators account is a requirement'
				}
			}
        }
    }

    Describe "Default Backup Compression" -Tags DefaultBackupCompression, Low, $filename {
        $defaultbackupcompression = Get-DbcConfigValue policy.backup.defaultbackupcompression
        if ($NotContactable -contains $psitem) {
            Context "Testing Default Backup Compression on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Default Backup Compression on $psitem" {
                It "Default Backup Compression is set to $defaultbackupcompression on $psitem" -Skip:((Get-Version -SQLInstance $psitem) -lt 10) {
                    Assert-BackupCompression -Instance $psitem -defaultbackupcompression $defaultbackupcompression
                }
            }
        }
    }

    Describe "OLE Automation" -Tags OLEAutomation, security, CIS, Medium, $filename {
        $OLEAutomation = Get-DbcConfigValue policy.oleautomation
        if ($NotContactable -contains $psitem) {
            Context "Testing OLE Automation on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing OLE Automation on $psitem" {
                It "OLE Automation is set to $OLEAutomation on $psitem" {
                    (Get-DbaSpConfigure -SqlInstance $psitem -ConfigName 'OleAutomationProceduresEnabled').ConfiguredValue -eq 1 | Should -Be $OLEAutomation -Because 'OLE Automation can introduce additional security risks'
                }
            }
        }
    }

    Describe "Error Log Entries" -Tags ErrorLog, Medium, $filename {
        $logWindow = Get-DbcConfigValue policy.errorlog.warningwindow
        if ($NotContactable -contains $psitem) {
            Context "Checking error log on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Checking error log on $psitem" {
                It "Error log should be free of error severities 17-24 on $psitem" {
                    Assert-ErrorLogEntry -AllInstanceInfo $AllInstanceInfo
                }
            }
        }
    }

    Describe "Error Log Count" -Tags ErrorLogCount, CIS, Low, $filename {
        $errorLogCount = Get-DbcConfigValue policy.errorlog.logcount
        if ($NotContactable -contains $psitem) {
            Context "Checking error log count on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Checking error log count on $psitem" {
                It "Error log count should be greater or equal to $errorLogCount on $psitem" {
                    Assert-ErrorLogCount -SqlInstance $psitem -errorLogCount $errorLogCount
                }
            }
        }
    }

    Describe "Instance MaxDop" -Tags MaxDopInstance, MaxDop, Medium, $filename {
        $UseRecommended = Get-DbcConfigValue policy.instancemaxdop.userecommended
        $MaxDop = Get-DbcConfigValue policy.instancemaxdop.maxdop
        $ExcludeInstance = Get-DbcConfigValue policy.instancemaxdop.excludeinstance

        if ($NotContactable -contains $psitem) {
            Context "Testing Instance MaxDop Value on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            if ($psitem -in $ExcludeInstance) {$Skip = $true}else {$skip = $false}
            Context "Testing Instance MaxDop Value on $psitem" {
                It "Instance Level MaxDop setting should be correct on $psitem" -Skip:$Skip {
                    Assert-InstanceMaxDop -Instance $psitem -UseRecommended:$UseRecommended -MaxDopValue $MaxDop
                }
            }
        }
    }

    Describe "Two Digit Year Cutoff" -Tags TwoDigitYearCutoff, Low, $filename {
        $twodigityearcutoff = Get-DbcConfigValue policy.twodigityearcutoff
        if ($NotContactable -contains $psitem) {
            Context "Testing Two Digit Year Cutoff on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Two Digit Year Cutoff on $psitem" {
                It "Two Digit Year Cutoff is set to $twodigityearcutoff on $psitem" {
                    Assert-TwoDigitYearCutoff -Instance $psitem -TwoDigitYearCutoff $twodigityearcutoff
                }
            }
        }
    }

    Describe "Trace Flags Expected" -Tags TraceFlagsExpected, TraceFlag, High, $filename {
        $ExpectedTraceFlags = Get-DbcConfigValue policy.traceflags.expected
        if ($NotContactable -contains $psitem) {
            Context "Testing Expected Trace Flags on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Expected Trace Flags on $psitem" {
                It "Expected Trace Flags $ExpectedTraceFlags exist on $psitem" {
                    Assert-TraceFlag -SQLInstance $psitem -ExpectedTraceFlag $ExpectedTraceFlags
                }
            }
        }
    }
	
    Describe "Trace Flags Not Expected" -Tags TraceFlagsNotExpected, TraceFlag, Medium, $filename {
        $NotExpectedTraceFlags = Get-DbcConfigValue policy.traceflags.notexpected
        if ($NotContactable -contains $psitem) {
            Context "Testing Not Expected Trace Flags on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Not Expected Trace Flags on $psitem" {
                It "Expected Trace Flags $NotExpectedTraceFlags to not exist on $psitem" {
                    Assert-NotTraceFlag -SQLInstance $psitem -NotExpectedTraceFlag $NotExpectedTraceFlags
                }
            }
        }
    }

    Describe "CLR Enabled" -Tags CLREnabled, security, CIS, High, $filename {
        $CLREnabled = Get-DbcConfigValue policy.security.clrenabled
        if ($NotContactable -contains $psitem) {
            Context "Testing CLR Enabled on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing CLR Enabled on $psitem" {
                It "CLR Enabled is set to $CLREnabled on $psitem" {
                    Assert-CLREnabled -SQLInstance $psitem -CLREnabled $CLREnabled
                }
            }
        }
    }

    Describe "Ad Hoc Distributed Queries" -Tags AdHocDistributedQueriesEnabled, security, CIS, Medium, $filename {
        $AdHocDistributedQueriesEnabled = Get-DbcConfigValue policy.security.AdHocDistributedQueriesEnabled
        if ($NotContactable -contains $psitem) {
            Context "Testing Ad Hoc Distributed Queries on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing Ad Hoc Distributed Queries on $psitem" {
                It "Ad Hoc Distributed Queries is set to $AdHocDistributedQueriesEnabled on $psitem" {
                    Assert-AdHocDistributedQueriesEnabled -SQLInstance $Psitem -AdHocDistributedQueriesEnabled $AdHocDistributedQueriesEnabled
                }
            }
        }
    }
	
    Describe "XP CmdShell" -Tags XpCmdShellDisabled, security, CIS, Medium, $filename {
        $XpCmdShellDisabled = Get-DbcConfigValue policy.security.XpCmdShellDisabled
        if ($NotContactable -contains $psitem) {
            Context "Testing XP CmdShell on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Testing XP CmdShell on $psitem" {
                It "XPCmdShell is set to $XpCmdShellDisabled on $psitem" {
                    Assert-XpCmdShellDisabled -SQLInstance $Psitem -XpCmdShellDisabled $XpCmdShellDisabled
                }
            }
        }
    }
	
    Describe "Default Trace" -Tags DefaultTrace, CIS, Low, $filename {
        $skip = Get-DbcConfigValue skip.instance.defaulttrace
        if ($NotContactable -contains $psitem) {
            Context "Checking Default Trace on $psitem" {
                It "Can't Connect to $Psitem" -Skip:$skip {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
            Context "Checking Default Trace on $psitem" {
                It "The Default Trace should be enabled on $psitem"  -Skip:$skip {
                    Assert-DefaultTrace -AllInstanceInfo $AllInstanceInfo
                }
            }
        }
    }
	
	Describe "SQL Agent Account" -Tags AgentServiceAccount, ServiceAccount, StartName, $filename {
		if ($NotContactable -contains $psitem) {
            Context "Testing SQL Agent is running on $psitem" {
                It "Can't Connect to $Psitem" -Skip:$skip {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
			Context "Testing SQL Agent is running on $psitem" {
				@(Get-DbaSqlService -ComputerName $psitem -Type Agent).ForEach{
					It "SQL Agent Should Be running on $($psitem.ServiceName)" {
						$psitem.State | Should -Be "Running" -Because 'The agent service is required to run SQL Agent jobs'
					}
					It "SQL Agent service should have a start mode of Automatic on $($psitem.ServiceName)" {
						$psitem.StartMode | Should -Be "Automatic" -Because 'Otherwise the Agent Jobs wont run if the server is restarted'
					}
					It "SQL Agent service account should be an domain account on $($psitem.ServiceName) -> $($psitem.StartName)" {
						$psitem.StartName | Should -Match $(((gwmi Win32_ComputerSystem).Domain).Split(".")[0]) -Because 'The SQL Server service has to run on a domain account'
					}
				}
			}
		}	
	}
	
	Describe "Valid Job Owner" -Tags ValidJobOwner, $filename {
		[string[]]$targetowner = Get-DbcConfigValue agent.validjobowner.name
		if ($NotContactable -contains $psitem) {
			Context "Testing job owners on $psitem" {
				It "Can't Connect to $Psitem" {
					$false  |  Should -BeTrue -Because "The instance should be available to be connected to!"
				}
			}
		}
		else {
			Context "Testing job owners on $psitem" {
				@(Get-DbaAgentJob -SqlInstance $psitem -EnableException:$false).ForEach{
					It "Job $($psitem.Name)  - owner $($psitem.OwnerLoginName) should be in this list ( $( [String]::Join(", ", $targetowner) ) ) on $($psitem.SqlInstance)" {
						$psitem.OwnerLoginName | Should -BeIn $TargetOwner -Because "The account that is the job owner is not what was expected"
					}
				}
			}
		}
	}
	
	Describe "Job History Configuration" -Tags JobHistory, $filename {
		if ($NotContactable -contains $psitem) {
			Context "Testing job history configuration on $psitem" {
				It "Can't Connect to $Psitem" {
					$false  |  Should -BeTrue -Because "The instance should be available to be connected to!"
				}
			}
		}
		else {    
			Context "Testing job history configuration on $psitem" {
				[int]$minimumJobHistoryRows = Get-DbcConfigValue agent.history.maximumhistoryrows
				[int]$minimumJobHistoryRowsPerJob = Get-DbcConfigValue agent.history.maximumjobhistoryrows

				$AgentServer = Get-DbaAgentServer -SqlInstance $psitem -EnableException:$false

				if ($minimumJobHistoryRows -eq -1) {
					It "The maximum job history configuration should be set to disabled on $psitem" {
						Assert-JobHistoryRowsDisabled -AgentServer $AgentServer -minimumJobHistoryRows $minimumJobHistoryRows
					}
				}
				else {
					It "The maximum job history number of rows configuration should be greater or equal to $minimumJobHistoryRows on $psitem" {
						Assert-JobHistoryRows -AgentServer $AgentServer -minimumJobHistoryRows $minimumJobHistoryRows
					}
					It "The maximum job history rows per job configuration should be greater or equal to $minimumJobHistoryRowsPerJob on $psitem" {
						Assert-JobHistoryRowsPerJob -AgentServer $AgentServer -minimumJobHistoryRowsPerJob $minimumJobHistoryRowsPerJob
					}
				}
			}
		}      
	}
}

Describe "SQL Browser Service" -Tags SqlBrowserServiceAccount, ServiceAccount, High, $filename {
    @(Get-ComputerName).ForEach{
        if ($NotContactable -contains $psitem) {
            Context "Testing SQL Browser Service on $psitem" {
                It "Can't Connect to $Psitem" {
                    $false	|  Should -BeTrue -Because "The instance should be available to be connected to!"
                }
            }
        }
        else {
			Context "Testing SQL Browser Service on $psitem" {

					$Services = Get-DbaService -ComputerName $psitem
						It "SQL browser service startmode should be Automatic on $psitem as multiple instances are installed" {
							$Services.Where{$_.ServiceType -eq 'Browser'}.StartMode | Should -Be "Automatic"
						}
				}

			}
        }
}

Set-PSFConfig -Module dbachecks -Name global.notcontactable -Value $NotContactable






# SIG # Begin signature block
# MIINEAYJKoZIhvcNAQcCoIINATCCDP0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVoPVIlYpUqnHOVhYhX6JCQnU
# ZUWgggpSMIIFGjCCBAKgAwIBAgIQAsF1KHTVwoQxhSrYoGRpyjANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTE3MDUwOTAwMDAwMFoXDTIwMDUx
# MzEyMDAwMFowVzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMQ8wDQYD
# VQQHEwZWaWVubmExETAPBgNVBAoTCGRiYXRvb2xzMREwDwYDVQQDEwhkYmF0b29s
# czCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI8ng7JxnekL0AO4qQgt
# Kr6p3q3SNOPh+SUZH+SyY8EA2I3wR7BMoT7rnZNolTwGjUXn7bRC6vISWg16N202
# 1RBWdTGW2rVPBVLF4HA46jle4hcpEVquXdj3yGYa99ko1w2FOWzLjKvtLqj4tzOh
# K7wa/Gbmv0Si/FU6oOmctzYMI0QXtEG7lR1HsJT5kywwmgcjyuiN28iBIhT6man0
# Ib6xKDv40PblKq5c9AFVldXUGVeBJbLhcEAA1nSPSLGdc7j4J2SulGISYY7ocuX3
# tkv01te72Mv2KkqqpfkLEAQjXgtM0hlgwuc8/A4if+I0YtboCMkVQuwBpbR9/6ys
# Z+sCAwEAAaOCAcUwggHBMB8GA1UdIwQYMBaAFFrEuXsqCqOl6nEDwGD5LfZldQ5Y
# MB0GA1UdDgQWBBRcxSkFqeA3vvHU0aq2mVpFRSOdmjAOBgNVHQ8BAf8EBAMCB4Aw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYDVR0fBHAwbjA1oDOgMYYvaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwNaAzoDGGL2h0
# dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMEwG
# A1UdIARFMEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3
# LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGEBggrBgEFBQcBAQR4MHYwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBOBggrBgEFBQcwAoZC
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJ
# RENvZGVTaWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQAD
# ggEBANuBGTbzCRhgG0Th09J0m/qDqohWMx6ZOFKhMoKl8f/l6IwyDrkG48JBkWOA
# QYXNAzvp3Ro7aGCNJKRAOcIjNKYef/PFRfFQvMe07nQIj78G8x0q44ZpOVCp9uVj
# sLmIvsmF1dcYhOWs9BOG/Zp9augJUtlYpo4JW+iuZHCqjhKzIc74rEEiZd0hSm8M
# asshvBUSB9e8do/7RhaKezvlciDaFBQvg5s0fICsEhULBRhoyVOiUKUcemprPiTD
# xh3buBLuN0bBayjWmOMlkG1Z6i8DUvWlPGz9jiBT3ONBqxXfghXLL6n8PhfppBhn
# daPQO8+SqF5rqrlyBPmRRaTz2GQwggUwMIIEGKADAgECAhAECRgbX9W7ZnVTQ7Vv
# lVAIMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0Rp
# Z2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzEwMjIxMjAwMDBaFw0yODEw
# MjIxMjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNI
# QTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQD407Mcfw4Rr2d3B9MLMUkZz9D7RZmxOttE9X/lqJ3bMtdx
# 6nadBS63j/qSQ8Cl+YnUNxnXtqrwnIal2CWsDnkoOn7p0WfTxvspJ8fTeyOU5JEj
# lpB3gvmhhCNmElQzUHSxKCa7JGnCwlLyFGeKiUXULaGj6YgsIJWuHEqHCN8M9eJN
# YBi+qsSyrnAxZjNxPqxwoqvOf+l8y5Kh5TsxHM/q8grkV7tKtel05iv+bMt+dDk2
# DZDv5LVOpKnqagqrhPOsZ061xPeM0SAlI+sIZD5SlsHyDxL0xY4PwaLoLFH3c7y9
# hbFig3NBggfkOItqcyDQD2RzPJ6fpjOp/RnfJZPRAgMBAAGjggHNMIIByTASBgNV
# HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDAzB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDig
# NoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDBPBgNVHSAESDBGMDgGCmCGSAGG/WwAAgQwKjAo
# BggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAKBghghkgB
# hv1sAzAdBgNVHQ4EFgQUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHwYDVR0jBBgwFoAU
# Reuir/SSy4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQELBQADggEBAD7sDVoks/Mi
# 0RXILHwlKXaoHV0cLToaxO8wYdd+C2D9wz0PxK+L/e8q3yBVN7Dh9tGSdQ9RtG6l
# jlriXiSBThCk7j9xjmMOE0ut119EefM2FAaK95xGTlz/kLEbBw6RFfu6r7VRwo0k
# riTGxycqoSkoGjpxKAI8LpGjwCUR4pwUR6F6aGivm6dcIFzZcbEMj7uo+MUSaJ/P
# QMtARKUT8OZkDCUIQjKyNookAv4vcn4c10lFluhZHen6dGRrsutmQ9qzsIzV6Q3d
# 9gEgzpkxYz0IGhizgZtPxpMQBvwHgfqL2vmCSfdibqFT+hKUGIUukpHqaGxEMrJm
# oecYpJpkUe8xggIoMIICJAIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQD
# EyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBAhACwXUo
# dNXChDGFKtigZGnKMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgACh
# AoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAM
# BgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQY/UyyFNReMHHbXG9PUklWOG1v
# AzANBgkqhkiG9w0BAQEFAASCAQBY1yL4MQt2oT6a+aMidW3pi3RwSoahwM1nFXQr
# oD8qufrrt3uR7EnluQDcHN07OGmEUMHdlMLt23NIqapc/f4YBvFlgRdcvzWCPfWq
# nq8a4Sslfi4x0g2UHIBYmstvKy1H3ztY/EGg/mrCXA+pGrCpJZsHjkQte8A7FSwR
# 9HEskbH5U6xQfiDIYSEC5O9D3FwbcqvT9VSqfF99NCLTa+B0U8uLGOCWAy6C6TyZ
# XpRwwzeN4Im4cOv2LHmUWVtFnQZ8m0wEBHyd4dLtfZF6NElf7x+IEttWFuzFvPw5
# 7ewR/pDi9COKaRNg9lpaEO9DLHiJ7F7DJsihxaW9+GwqFYRU
# SIG # End signature block
