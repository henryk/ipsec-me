# ipsec-me (c) Henryk Plötz

SHELL=/bin/bash
PROJECT_NAME=ipsec-me
MOD_NAME=ipsec_me
WATCHMEDO_PATH=$$(which watchmedo)
NOSETESTS_PATH=$$(which nosetests)
TEST_CMD=SETTINGS=$$PWD/etc/conf/testing.conf SILENCE_DEPRECATION=1 $(NOSETESTS_PATH) $(MOD_NAME)

install:
	python setup.py install

requirements:
	pip install -r requirements.txt

clean:
	rm -rf build dist *.egg-info
	find . -name '*.pyc' -delete
	find . -name __pycache__ -delete

server:
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py runserver

shell:
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py shell

watch:
	watchmedo shell-command -R -p "*.py" -c 'echo \\n\\n\\n\\nSTART; date; $(TEST_CMD) -c etc/nose/test-single.cfg; date' .

test:
	$(TEST_CMD) -c etc/nose/test.cfg

single:
	$(TEST_CMD) -c etc/nose/test-single.cfg

db:
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py init_db
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py user_add --email "guest@example.com" --password "guest"
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py user_add --email "admin@example.com" --password "axw" --admin
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py vpn_create --name "Office-VPN" --hostname "office.vpn.example.com" --base-dn "OU=VPN, O=Example Inc., C=US" --user "guest@example.com" --admin-user "admin@example.com"

newmigration:
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py drop_db
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py db upgrade
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py db migrate

migrate:
	SETTINGS=$$PWD/etc/conf/dev.conf bin/manage.py db upgrade

apidocs:
	rm -rf var/sphinx/auto-api
	mkdir -p var/sphinx/auto-api/$(MOD_NAME)
	sphinx-apidoc --separate -o var/sphinx/auto-api/$(MOD_NAME) $(MOD_NAME) $(MOD_NAME)/tests
	-rm docs/auto-api
	ln -s $$PWD/var/sphinx/auto-api docs/auto-api

docs:
	rm -rf build/sphinx
	SETTINGS=$$PWD/etc/conf/testing.conf sphinx-build -b html docs build/sphinx

notebook:
	SETTINGS=$$PWD/etc/conf/dev.conf cd var/ipython && ipython notebook

release:
	python setup.py sdist upload -r https://pypi.python.org/pypi

.PHONY: clean install test server watch notebook db single docs shell upgradedb migratedb release requirements apidocs gh-pages
