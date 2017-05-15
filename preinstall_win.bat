deps\python-2.7.12.amd64.msi /qb
setx path "%path%;C:\Python27;C:\Python27\Scripts;"
pip install --upgrade pip
pip install wheel
pip install unicorn
wheel install capstone-3.0.5rc2-py2-none-win_amd64.whl
pip install cryptography
pip install win_inet_pton