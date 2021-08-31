FROM python:2.7-windowsservercore-1809 

WORKDIR /usr/bin/ 

RUN C:\python\python.exe -m pip install --upgrade pip

RUN pip --trusted-host pypi.python.org --trusted-host files.pythonhosted.org --trusted-host pypi.org install --upgrade pip requests setuptools --user

RUN pip install requests[security] --user

COPY commonutil.py /usr/bin/commonutil.py
COPY entrypoint.py /usr/bin/entrypoint.py
COPY cacerts.py /usr/bin/cacerts.py
COPY vault.py /usr/bin/vault.py
ADD certs /usr/local/certs
ENTRYPOINT ["python", "/usr/bin/entrypoint.py"]