import os
import subprocess

def create_directories():
    # List of directory names to create
    directories = ["db", "edge"]
    
    for directory in directories:
        # Check if the directory already exists
        if not os.path.exists(directory):
            # Create the directory
            os.makedirs(directory)
            print(f"Directory '{directory}' created.")
        else:
            print(f"Directory '{directory}' already exists.")

def run_scripts():
    # List of scripts to run in sequence
    scripts = ["getData.py", "parseStix.py", "importArango.py"]
    
    for script in scripts:
        # Run the script
        print(f"Running {script}...")
        subprocess.run(["python", script], check=True)

def main():
    # Create required directories
    create_directories()
    
    # Run the scripts in sequence
    run_scripts()

if __name__ == "__main__":
    main()