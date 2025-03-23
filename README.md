# Ghidorah0x1
Ghidorah0x1 is a SAST (Static Application Security Testing) and LLM (Large Language Model) implementation built with the Django framework. This project integrates security scanning tools such as Snyk and Semgrep to help identify security vulnerabilities in your codebase. It also provides a set of APIs that you can interact with via Postman.

# Features
* **Static Analysis:** Utilizes Snyk and Semgrep to perform static code analysis and detect vulnerabilities.
* **Django-based Application**: Built on the Django framework, providing a scalable web application structure.    
* **Postman Integration**: APIs are accessible via Postman using the provided collection.

# Prerequisites
Before setting up Ghidorah0x1, ensure that your environment meets the following requirements:

1. **Django**
Make sure you have Django installed in your environment. You can install it via pip:    
`pip install django`

2. **Snyk Binary**    
This project requires the Snyk binary to be present in the Ghidorah/Ghidorah/binaries/ directory of your host machine.        
Steps to set up Snyk:     
    * Download the Snyk binary from the Snyk website that matches your operating system.      
    * Create a folder structure like Ghidorah/Ghidorah/binaries/ if it does not exist.     
    * Place the downloaded Snyk binary inside the binaries folder.     

3. **Semgrep**     
Semgrep is also required for static code analysis. You can install it using pip: `pip install semgrep` (Upon running the `start_server` command, it automatically downloads the semgrep binary if it doesn't present in the environment)

4. **MYSQL**    
Set-up a MySQL instance on your machine and provide the required values to `.env` file. Location of this file should be at the root folder of this project i.e., `Ghidorah0x1`
    ```
    db_name=database_name
    db_user=database_user_name
    db_password=database_user_password
    host_user=localhost
    app_port=3306
    ```

# Setup
Clone the repository to your local machine: `git clone <repository-url>`     

Navigate to the project directory: `cd Ghidorah0x1`    

Install the necessary dependencies: `pip install -r requirements.txt`    

_Ensure that both Snyk and Semgrep are properly set up as described in the prerequisites._

# Usage
Starting the Server
To start the Django development server, use the following command: `python manage.py start_server`    

This will start the server on port 8000 by default.

# Postman Integration
Once the server is running, you can interact with the available APIs using Postman:

Import the provided Postman collection (postman_collections.json) into Postman.

Use the collection to make requests to the running server.

# SAST Scans
The project integrates Snyk and Semgrep for static analysis of your codebase. To trigger the SAST scan, the server will automatically run these tools in the background during the process of testing the APIs.

# Troubleshooting
**Snyk binary missing**: If you encounter issues related to the Snyk binary, ensure it is downloaded and placed in the Ghidorah/Ghidorah/binaries/ directory.

**Semgrep errors**: Ensure that you have the correct version of Semgrep installed and that the dependencies are configured correctly.

**Port conflicts:** If port 8000 is already in use, you can specify a different port using the --port option when starting the server.
