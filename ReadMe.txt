SafeKeep is a comprehensive cybersecurity application designed to enhance the 
security posture of Linux hosts. It provides robust tools for real-time monitoring 
and management of network activities, ensuring proactive defense against a wide 
range of cyber threats.

Install virtual environment
pip install virtualenv

Create a Virtual Environment:
Navigate to your project directory and run:
virtualenv venv

Activate the Virtual Environment:
In bash
source venv/bin/activate
In batch
venv\Scripts\activate

Ensure Your Virtual Environment is Activated:
You should see the name of your virtual environment (e.g., (venv))
at the beginning of your command line prompt. This indicates that 
any Python packages you install will only affect this virtual environment, 
rather than your global Python installation.

To generate a requirements.txt 
in bash
pip freeze > requirements.txt

To install all dependencies 
in bash
pip install -r requirements.txt