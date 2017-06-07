PYTHON_SITE_PACKAGES_PATH := \
	$(shell python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")

help:
	@echo "TODO: Write the install help"

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

install:
	pip install -r requirements_dev.txt
	@echo "Yay! Everything installed."


test:
ifeq ($(filter-out $@,$(MAKECMDGOALS)), "")
	@echo "Running all tests"
else
	@echo "Running only tests in $(filter-out $@,$(MAKECMDGOALS))"
endif
	nosetests -sv -a is_unit --with-yanc $(filter-out $@,$(MAKECMDGOALS))