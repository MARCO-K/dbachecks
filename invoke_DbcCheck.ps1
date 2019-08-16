$sqlInstance = ''
$computerName = ''
$exclude = @('AgentAlert','CertificateExpiration','ClusterHealth','DatabaseGrowthEvent','DatabaseMailEnabled','DatabaseMailProfile','DbaOperator','DisabledIndex','DuplicateIndex','FailedJob','FailsafeOperator','HADR','InstanceConnection','LastBackup','LastDiffBackup','LastFullBackup','LastGoodCheckDb','LastJobRunTime','LastLogBackup','LinkedServerConnection','LogShipping','LogShippingPrimary','LogShippingSecondary','LongRunningJob','MaintenanceSolution','MemoryDump','NetworkLatency','OlaInstalled','OlaJobs','PseudoSimple','RecoveryModel','SPN','TestLastBackup','TestLastBackupVerifyOnly','UnusedIndex','UserDiff','UserFull','UserIndexOptimize','WhoIsActiveInstalled','XESessionRunning','XESessionRunningAllowed','XESessionStopped')

$result = Invoke-DbcCheck -SqlInstance $sqlInstance -ComputerName $computerName -AllChecks -show all -PassThru

Foreach ($res in $result.TestResult) {
    [System.Array]$Object += [PSCustomObject]@{
        Describe = $res.Describe.TrimEnd(':')
        Context = $res.Context.TrimEnd(':')
        It = $res.Name.TrimEnd(':')
        Should = $res.Result
        Time = $res.Time
    }
} 
 
# $Object
# $Object | Format-Table -Autosize
$object | convertto-csv -NoTypeInformation -Delimiter ';' | clip
#$Object | Export-Csv -Path 'D:\install\PesterExport.csv' -NoTypeInformation