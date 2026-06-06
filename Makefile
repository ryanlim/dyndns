dns_checker:
	pyinstaller -F nsupdate.py
	install -m 755 dist/nsupdate nsupdate

clean:
	pyinstaller --clean nsupdate.py
