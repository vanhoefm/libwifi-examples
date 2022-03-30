# Installation

Clone the repository including submodules:

	git clone https://github.com/vanhoefm/libwifi-examples.git --recursive
	cd libwifi-examples

Create a virtual python environmont:

	python3 -m venv venv
	source venv/bin/activate
	pip install -r libwifi/requirements.txt


# Usage

Load the virtual python environment as root and run any of the examples:

	sudo su
	source venv/bin/activate
	./beacon_csa_attack.py wlp0s20f3 PLDTHOMEFIBRa0208 --target 00:11:22:33:44:55

