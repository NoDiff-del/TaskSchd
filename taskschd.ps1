$taskDir = "C:\Windows\System32\Tasks"

$suspiciousKeywords = @(
    "CMD",
    "Type",
    "Echo",
    "Powershell",
    "Powershell_ISE",
    "PowershellISE",
    "TaskScheduler",
    "Task_Scheduler",
    "MMC"
)

Write-Host "Scanning tasks in $taskDir and subfolders..." -ForegroundColor Yellow

function Process-TaskFile {
    param (
        [string]$taskFilePath
    )
    try {
        $taskXml = Get-Content -Path $taskFilePath -Raw -ErrorAction Stop
        $task = [xml]$taskXml

        if (-not $task.Task.Actions) {
            return
        }

        foreach ($action in $task.Task.Actions.Exec) {
            $command = $action.Command
            $arguments = $action.Arguments

            if ($command) {
                Write-Host (" ")
                Write-Host ("Scanning task: {0}" -f $taskFilePath) -ForegroundColor Yellow
                Write-Host ("Command: {0}" -f $command) -ForegroundColor Cyan

                if ($arguments) {
                    Write-Host ("Arguments: {0}" -f $arguments) -ForegroundColor Cyan
                }
                foreach ($keyword in $suspiciousKeywords) {
                    $regex = "\b$keyword\b"
                    if ($command -match $regex -or $arguments -match $regex) {
                        Write-Host ("Detected suspicious keyword: {0}" -f $keyword) -ForegroundColor Red
                    }
                }
            }
        }

    } catch {
        Write-Host ("Error processing {0}: {1}" -f $taskFilePath, $_.Exception.Message) -ForegroundColor Red
    }
}

$allTasks = Get-ChildItem -Path $taskDir -Recurse -File
$totalTasks = $allTasks.Count
$counter = 0

foreach ($taskFile in $allTasks) {
    $counter++

    Process-TaskFile -taskFilePath $taskFile.FullName
}

Write-Host "`nScan complete! Processed $counter tasks." -ForegroundColor Green
