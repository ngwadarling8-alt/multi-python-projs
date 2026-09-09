


# Python Virtual Environment Setup in VS Code

## Introduction

Today I created and configured a Python virtual environment for my FIM2 project using VS Code on Windows.

A virtual environment allows a Python project to have its own packages and Python environment without affecting other projects on the computer.

## Step 1: Opened VS Code

I opened Visual Studio Code and opened the terminal.

The terminal initially showed:

```text
(venv) C:\Users\ALL COMPUTERS>
````

This showed that a virtual environment was already active, but it was not located inside my project folder.

## Step 2: Created the FIM2 Project Folder

I created a project folder called `FIM2` using:

```text
mkdir FIM2
```

## Step 3: Entered the FIM2 Folder

I moved into the project folder using:

```text
cd FIM2
```

The terminal then showed:

```text
PS C:\Users\ALL COMPUTERS\FIM2>
```

## Step 4: Checked the Folder

I used:

```text
dir
```

The folder was empty, which meant that the virtual environment had not yet been created inside the FIM2 project.

## Step 5: Created the Virtual Environment

I created a new virtual environment inside the FIM2 folder using:

```text
python -m venv venv
```

This created a folder called `venv`.

The `venv` folder contains the files needed for the project's isolated Python environment.

## Step 6: Encountered a PowerShell Error

When I tried to activate the environment using:

```text
.\venv\Scripts\Activate.ps1
```

PowerShell displayed an error saying that running scripts was disabled on the system.

This happened because PowerShell's execution policy was preventing the activation script from running.

Instead of changing the PowerShell security settings, I used Command Prompt.

## Step 7: Switched to Command Prompt

I opened Command Prompt in the VS Code terminal.

The terminal showed:

```text
C:\Users\ALL COMPUTERS>
```

I then entered the FIM2 project folder:

```text
cd FIM2
```

The terminal showed:

```text
C:\Users\ALL COMPUTERS\FIM2>
```

## Step 8: Activated the Virtual Environment

I activated the virtual environment using:

```text
venv\Scripts\activate
```

The terminal then showed:

```text
(venv) C:\Users\ALL COMPUTERS\FIM2>
```

The `(venv)` at the beginning confirmed that the virtual environment was successfully activated.

## Step 9: Selected the Environment in VS Code

I selected the Python interpreter in VS Code using:

**Ctrl + Shift + P**

Then I selected:

**Python: Select Interpreter**

I selected the Python interpreter inside the `venv` folder.

The `venv` indicator appeared at the bottom-right of VS Code.

This confirmed that VS Code was using the virtual environment for the FIM2 project.

## Final Project Structure

The project now has this basic structure:

```text
FIM2/
│
├── venv/
│
└── Python project files
```

## Useful Commands

### Create a virtual environment

```text
python -m venv venv
```

### Activate in Command Prompt

```text
venv\Scripts\activate
```

### Activate in PowerShell

```text
.\venv\Scripts\Activate.ps1
```

### Check Python version

```text
python --version
```

### Deactivate the environment

```text
deactivate
```

## Conclusion

I successfully created a Python virtual environment inside my `FIM2` project, activated it using Command Prompt, and selected it as the Python interpreter in VS Code.

The final terminal confirmed the setup with:

```text
(venv) C:\Users\ALL COMPUTERS\FIM2>
```

