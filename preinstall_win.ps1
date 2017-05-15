If( !(Test-Path "C:\Python27\Scripts\pip.exe") ){
  $process="deps\python-2.7.12.amd64.msi"
  $args="/qb"
  Start-Process $process -ArgumentList $args -Wait
}

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

python setup.py build
python setup.py install

