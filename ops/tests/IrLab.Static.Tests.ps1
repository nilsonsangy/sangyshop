<#
.SYNOPSIS
    Pester 5.x static checks over the incident response lab files.

.DESCRIPTION
    Reads text only; no script is executed and no cloud CLI is invoked.

    Scanned areas: ops/aws/ir-lab, ops/azure/ir-lab, ops/lib, ops/aws/iam and
    ops/tests (this file excluded from the text scans because it holds the
    patterns it searches for).

    Checks:
      * No lab script climbs out of the repository to reach a core library
        folder, and no script has a -SangyShopPath parameter.
      * Independence: no text file in the repository mentions the sibling tool
        project (case-insensitive) or any teaching context. Generic words
        such as class, db-instance-class and storage class are allowed. The
        forbidden terms are assembled at runtime so this file never spells
        them.
      * No em dash or en dash in any text file.
      * No Portuguese words (accented letters or a list of unambiguous words).
      * No spec numbering labels in any scanned file.
      * No hard-coded e-mail address, except reserved example domains.
      * Every PowerShell file parses without errors.
      * Every AWS lab entry script has a "Required IAM actions:" header block.

    Run with:
        Invoke-Pester -Path ops/tests/IrLab.Static.Tests.ps1
#>

BeforeDiscovery {
    $script:OpsRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
    $selfName = 'IrLab.Static.Tests.ps1'

    $areas = @('aws/ir-lab', 'azure/ir-lab', 'lib', 'aws/iam', 'tests')
    $textExt = @('.ps1', '.psm1', '.md', '.json', '.py', '.kql', '.sh', '.tpl', '.txt', '.yaml', '.yml', '.example')

    $all = foreach ($a in $areas) {
        $dir = Join-Path $script:OpsRoot $a
        if (Test-Path -LiteralPath $dir) {
            Get-ChildItem -LiteralPath $dir -Recurse -File |
                Where-Object { $_.FullName -notmatch '__pycache__' -and
                               ($textExt -contains $_.Extension) -and
                               $_.Name -ne $selfName }
        }
    }

    $script:TextFiles = @($all | ForEach-Object {
        @{ Path = $_.FullName; Rel = $_.FullName.Substring($script:OpsRoot.Length + 1).Replace('\', '/') }
    })

    # Scripts only, outside the tests folder.
    $script:LabScripts = @($script:TextFiles | Where-Object {
        $_.Path -like '*.ps1' -and $_.Rel -notlike 'tests/*' })

    $script:AllPs1 = @($script:TextFiles | Where-Object { $_.Path -like '*.ps1' })

    # AWS lab entry scripts that must document the IAM actions they need.
    $script:AwsEntry = @($script:TextFiles | Where-Object {
        $_.Rel -like 'aws/ir-lab/*' -and $_.Path -like '*.ps1' -and
        ((Split-Path $_.Path -Leaf) -match '^(enable|disable)-.+\.ps1$' -or
         (Split-Path $_.Path -Leaf) -in @('deploy-blocker.ps1', 'remove-blocker.ps1',
             'plant-leaked-credential.ps1', 'full-teardown.ps1')) })

    # Every scanned text file is checked for spec numbering labels.
    $script:NumberingFiles = @($script:TextFiles)

    # Repository-wide file list for the independence scan (read-only walk of
    # the working tree, mirroring what .gitignore leaves tracked).
    $repoRoot = (Resolve-Path (Join-Path $script:OpsRoot '..')).ProviderPath
    $skipDirs = @('.git', '.kiro', 'node_modules', 'logs', '.hypothesis', '.pytest_cache', '__pycache__', 'out')
    $indepExt = @('.ps1', '.psm1', '.md', '.json', '.py', '.kql', '.sh', '.tpl', '.txt', '.yaml', '.yml',
                  '.example', '.js', '.mjs', '.cjs', '.html', '.css', '.sql', '.toml', '.cfg', '.ini', '.conf')
    $indepNames = @('Dockerfile', '.dockerignore', '.gitignore')
    $skipFiles = @('.env', 'db_password.txt', 'cloud.config.ps1', 'package-lock.json')

    $script:IndependenceFiles = @(
        Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Force |
            Where-Object {
                $rel = $_.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
                $segs = $rel.Split('/')
                $inSkipDir = $false
                for ($i = 0; $i -lt $segs.Count - 1; $i++) { if ($skipDirs -contains $segs[$i]) { $inSkipDir = $true } }
                -not $inSkipDir -and
                -not ($skipFiles -contains $_.Name) -and
                -not ($_.Name -like 'lab-manifest*.json' -and $_.Name -ne 'lab-manifest.example.json') -and
                -not ($_.Name -like '.env.*' -and $_.Name -ne '.env.example') -and
                -not ($_.Name -like '*.log') -and
                -not ($_.FullName -like '*.db*') -and
                (($indepExt -contains $_.Extension) -or ($indepNames -contains $_.Name))
            } | ForEach-Object {
                @{ Path = $_.FullName; Rel = $_.FullName.Substring($repoRoot.Length + 1).Replace('\', '/'); IsSelf = ($_.Name -eq $selfName) }
            }
    )}

BeforeAll {
    # Returns "relative:line: text" for each line of the file matching the regex.
    function Get-Hit {
        param([string] $Path, [string] $Rel, [string] $Pattern, [switch] $CaseSensitive)
        $n = 0
        foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
            $n++
            $hit = if ($CaseSensitive) { [regex]::IsMatch($line, $Pattern) }
                   else { [regex]::IsMatch($line, $Pattern, 'IgnoreCase') }
            if ($hit) { '{0}:{1}: {2}' -f $Rel, $n, $line.Trim() }
        }
    }

    $script:PtWords = @(
        'voce', 'nao', 'uma', 'para', 'porque', 'quando', 'sera', # lang-ignore: forbidden-word list for the language guard
        'usuario', 'arquivo', 'arquivos', 'ataque', 'aluno', 'alunos', ('au' + 'la'), ('au' + 'las'), # lang-ignore: forbidden-word list for the language guard
        'professor', 'credencial', 'deteccao', 'bloqueio', 'relatorio', # lang-ignore: forbidden-word list for the language guard
        'caminho', 'pasta', 'senha', 'erro', 'ambiente', 'laboratorio', # lang-ignore: forbidden-word list for the language guard
        'exemplo', 'obrigatorio', 'antes', 'depois', 'apenas', 'somente', 'tambem', # lang-ignore: forbidden-word list for the language guard
        'isso', 'esse', 'essa', 'seu', 'sua', 'conta', 'nome', 'valor', # lang-ignore: forbidden-word list for the language guard
        'ajuda', 'configuracao', 'resposta', 'incidente', 'etapa', 'passo' # lang-ignore: forbidden-word list for the language guard
    )
    $script:PtPattern = '\b(' + (($script:PtWords | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\b'

    # Reserved example domains are the only allowed e-mail hosts.
    $script:MailPattern = '[A-Za-z0-9._%+\-]+@(?![A-Za-z0-9.\-]*example\.(com|org|net)\b)[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}'

    # Independence patterns, assembled from fragments at runtime so that this
    # file never contains the forbidden terms.
    $script:SiblingPattern = ('nim', 'bus') -join ''
    $script:CoursePatterns = @(
        (('les', 'son\s+\d+') -join ''),
        (('\bcou', 'rse\b') -join ''),
        (('during', '\s+cl', 'ass\b') -join ''),
        (('cl', 'assroom') -join ''),
        (('\bstu', 'dents?\b') -join ''),
        (('\bau', 'las?\b') -join '')
    )
    # Built from code points so this file contains no dash characters.
    $script:DashPattern = '[' + [char]0x2013 + [char]0x2014 + ']'
}

Describe 'Lab text files are present' {
    It 'finds files to scan in <Area>' -ForEach @(
        @{ Area = 'aws/ir-lab' }, @{ Area = 'azure/ir-lab' }, @{ Area = 'lib' },
        @{ Area = 'aws/iam' }, @{ Area = 'tests' }
    ) {
        Test-Path (Join-Path (Join-Path $PSScriptRoot '..') $Area) | Should -BeTrue
    }
}

Describe 'No dependency on the original repository layout' {
    It 'has no climb to a core library folder in <Rel>' -ForEach $script:LabScripts {
        # A relative walk up the tree ending in the core library folder.
        $hits = Get-Hit -Path $Path -Rel $Rel -Pattern '\.\.[\\/][^''"\r\n]*ir_lab_core'
        $hits | Should -BeNullOrEmpty
    }

    It 'has no -SangyShopPath parameter or reference in <Rel>' -ForEach $script:TextFiles {
        $hits = Get-Hit -Path $Path -Rel $Rel -Pattern 'SangyShopPath'
        $hits | Should -BeNullOrEmpty
    }
}

Describe 'Text style' {
    It 'has no em dash or en dash in <Rel>' -ForEach $script:TextFiles {
        $hits = Get-Hit -Path $Path -Rel $Rel -Pattern $script:DashPattern
        $hits | Should -BeNullOrEmpty
    }

    It 'has no Portuguese words or accented letters in <Rel>' -ForEach $script:TextFiles {
        $accents = [string]::new([char[]](0xE1, 0xE0, 0xE2, 0xE3, 0xE9, 0xEA, 0xED, 0xF3, 0xF4, 0xF5, 0xFA, 0xE7,
                                         0xC1, 0xC0, 0xC2, 0xC3, 0xC9, 0xCA, 0xCD, 0xD3, 0xD4, 0xD5, 0xDA, 0xC7))
        $hits = @()
        $hits += Get-Hit -Path $Path -Rel $Rel -Pattern ('[' + $accents + ']')
        $hits += Get-Hit -Path $Path -Rel $Rel -Pattern $script:PtPattern
        $hits | Should -BeNullOrEmpty
    }

    It 'has no spec numbering labels in <Rel>' -ForEach $script:NumberingFiles {
        $pattern = '\b(Requirements?|Req)\s+\d|design\s+D-\d|\bProperty\s+\d+|\btasks?\s+\d+(\.\d+)?|\bProperties\s+\d|\bValidates:'
        $hits = Get-Hit -Path $Path -Rel $Rel -Pattern $pattern -CaseSensitive
        $hits | Should -BeNullOrEmpty
    }

    It 'has no hard-coded e-mail address in <Rel>' -ForEach $script:TextFiles {
        $hits = Get-Hit -Path $Path -Rel $Rel -Pattern $script:MailPattern
        $hits | Should -BeNullOrEmpty
    }
}

Describe 'PowerShell syntax' {
    It 'parses <Rel> without errors' -ForEach $script:AllPs1 {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors) | Out-Null
        @($errors | ForEach-Object { '{0}:{1}: {2}' -f $Rel, $_.Extent.StartLineNumber, $_.Message }) |
            Should -BeNullOrEmpty
    }
}

Describe 'AWS lab script headers' {
    It 'lists the required IAM actions in <Rel>' -ForEach $script:AwsEntry {
        $head = (Get-Content -LiteralPath $Path -TotalCount 120) -join "`n"
        $head | Should -Match 'Required IAM actions:'
    }

    It 'covers the expected entry scripts' -ForEach @(@{ Count = $script:AwsEntry.Count }) {
        $Count | Should -BeGreaterThan 10
    }
}

Describe 'Independence from other projects and teaching material' {
    It 'has no sibling tool token (any case) in <Rel>' -ForEach ($script:IndependenceFiles | Where-Object { -not $_.IsSelf }) {
        $hits = @()
        $hits += Get-Hit -Path $Path -Rel $Rel -Pattern $script:SiblingPattern
        # The path itself must not carry the token either.
        if ([regex]::IsMatch($Rel, $script:SiblingPattern, 'IgnoreCase')) { $hits += "$Rel (path)" }
        $hits | Should -BeNullOrEmpty
    }

    It 'has no teaching reference in <Rel>' -ForEach $script:IndependenceFiles {
        $hits = @()
        foreach ($pattern in $script:CoursePatterns) {
            $hits += Get-Hit -Path $Path -Rel $Rel -Pattern $pattern
        }
        $hits | Should -BeNullOrEmpty
    }

    It 'does not spell the sibling tool token in this test file' {
        $hits = Get-Hit -Path $PSCommandPath -Rel 'ops/tests/IrLab.Static.Tests.ps1' -Pattern $script:SiblingPattern
        $hits | Should -BeNullOrEmpty
    }

    It 'allows generic uses of the word class' -ForEach @(
        @{ Line = 'class Foo { }' }, @{ Line = 'db-instance-class db.t3.micro' },
        @{ Line = 'storage class STANDARD_IA' }, @{ Line = 'a CSS class attribute' }
    ) {
        $matched = @($script:CoursePatterns | Where-Object { [regex]::IsMatch($Line, $_, 'IgnoreCase') })
        $matched | Should -BeNullOrEmpty
    }

    It 'has files to scan' -ForEach @(@{ Count = @($script:IndependenceFiles).Count }) {
        $Count | Should -BeGreaterThan 20
    }
}