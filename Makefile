.PHONY: install clean docs

install:
	pip install -e .[docs,test,async]
	pip install bumpversion twine wheel

clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

release:
	pip install twine wheel
	rm -rf dist/*
	python setup.py sdist bdist_wheel
	twine upload -s dist/*
