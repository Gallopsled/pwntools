If( !(Test-Path "C:\Python27\Scripts\pip.exe") ){
  Write-Host "[+] Downloading and installing python 2.7.13 (with pip)"
  (New-Object System.Net.WebClient).DownloadFile('https://www.python.org/ftp/python/2.7.13/python-2.7.13.amd64.msi','deps\python-2.7.13.amd64.msi')
  $process="deps\python-2.7.13.amd64.msi"
  $args="/qb"
  Start-Process $process -ArgumentList $args -Wait
}

Write-Host "[+] Downloading and installing VCForPython 2.7"
(New-Object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi','deps\VCForPython27.msi')
$process="deps\VCForPython27.msi"
$args="/qb"
Start-Process $process -ArgumentList $args -Wait
  

$cur_path = [System.Environment]::GetEnvironmentVariable("Path","User")
If( !($cur_path -like "C:\Python27" )){
   setx path "%path%;C:\Python27;C:\Python27\Scripts;"
   $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";C:\Python27;C:\Python27\Scripts"
}

pip install --upgrade pip
pip install wheel
pip install unicorn
wheel install deps\capstone-3.0.5rc2-py2-none-win_amd64.whl
pip install cryptography
pip install win_inet_pton
pip install pynacl

python setup.py build
python setup.py install

