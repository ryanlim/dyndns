dns_checker:
	pyinstaller -F nsupdate.py

clean:
	pyinstaller --clean nsupdate.py
