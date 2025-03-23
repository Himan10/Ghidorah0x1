"""Overriding the exsiting runserver command to extend the logic
Things to do prior to runserver
1. check packages 
2. install packages if they are not present
"""

import os
import subprocess
import sys
from django.core.management.commands.runserver import Command as RunserverCommand
from django.core.management.base import CommandError

class Command(RunserverCommand):
    help = 'Runs the development server with additional setup checks'

    def handle(self, *args, **options):
        if not os.environ.get("ghidorah_scans_setup_done"):
            self.check_virtualenv()
            self.check_pip_installed()
            self.check_npm_installed()
            self.check_and_install_packages()
            os.environ["ghidorah_scans_setup_done"] = "True"

        # Call the original runserver handle method
        super().handle(*args, **options)

    def check_virtualenv(self):
        """check if the virtualenv is activated or not"""
        if sys.prefix == sys.base_prefix:
            raise CommandError("Virtual environment is not activated. Please activate your virtual environment.")
        else:
            sys.stdout.write(self.style.SUCCESS("Virtual environment is activated\n"))

    def check_pip_installed(self):
        """check if pip is installed on the machine or not"""
        try:
            subprocess.run(['which', 'pip'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sys.stdout.write(self.style.SUCCESS("pip is already installed\n"))
        except subprocess.CalledProcessError:
            raise CommandError("pip is not installed. Please install pip.\n")

    def check_npm_installed(self):
        """check if npm is installed on the machine or not"""
        try:
            subprocess.run(['which', 'npm'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sys.stdout.write(self.style.SUCCESS("npm is already installed\n"))
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise CommandError("npm is not installed. Please install npm.\n")
        
    def check_and_install_packages(self):
        """install the list below packages on the machine
        1. snyk-to-html using npm
        2. semgrep using pip
        """
        try:
            # check if semgrep is present
            semgrep_command_result = subprocess.run(["which", "semgrep"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if semgrep_command_result.returncode:
                semgrep_command_result = subprocess.run(["python", "-m", "pip", "install", "semgrep"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                sys.stdout.write(self.style.SUCCESS("Semgrep is successfully installed...\n"))
            else:
                sys.stdout.write(self.style.SUCCESS("Semgrep is already installed\n"))

            # check if snyk-to-html is present
            snyk_to_html_command_result = subprocess.run(["which", "snyk-to-html"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if snyk_to_html_command_result.returncode:
                snyk_to_html_command_result = subprocess.run(["npm", "install", "snyk-to-html", "-g"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                sys.stdout.write(self.style.SUCCESS("snyk-to-html is successfully installed\n"))
            else:
                sys.stdout.write(self.style.SUCCESS("snyk-to-html is already installed\n"))

        except (subprocess.SubprocessError, subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception):
            sys.stdout.write(self.style.ERROR("Error installing snyk-to-html using npm!!!\n"))
                

        