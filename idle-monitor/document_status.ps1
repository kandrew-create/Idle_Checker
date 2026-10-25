# Read existing Office instances only. Never open, save, activate, or close documents.
param([string]$Applications = '')
$ErrorActionPreference = 'Stop'
$wanted = $Applications.Split(',')
$records = @()
$providers = @(
    @{ Process = 'winword.exe'; ProgId = 'Word.Application'; Collection = 'Documents' },
    @{ Process = 'excel.exe'; ProgId = 'Excel.Application'; Collection = 'Workbooks' },
    @{ Process = 'powerpnt.exe'; ProgId = 'PowerPoint.Application'; Collection = 'Presentations' }
)
foreach ($provider in $providers) {
    if ($wanted -notcontains $provider.Process) { continue }
    $application = $null
    try {
        $application = [Runtime.InteropServices.Marshal]::GetActiveObject($provider.ProgId)
        $documents = $application.($provider.Collection)
        foreach ($document in $documents) {
            $saved = [bool]$document.Saved
            $hasPath = -not [string]::IsNullOrEmpty([string]$document.Path)
            foreach ($window in $document.Windows) {
                $records += [pscustomobject]@{
                    hwnd = [long]$window.Hwnd
                    name = [string]$document.Name
                    saved = $saved
                    has_path = $hasPath
                }
            }
        }
    } catch {
        # Busy, protected, unregistered, or inaccessible Office instances stay Unknown.
    } finally {
        if ($null -ne $application) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($application)
        }
    }
}
ConvertTo-Json -InputObject @($records) -Compress -Depth 3
