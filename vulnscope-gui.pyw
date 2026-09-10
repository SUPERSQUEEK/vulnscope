# Double-click entry point for the vulnscope GUI.
#
# The .pyw extension tells Windows to run this with pythonw.exe, which launches
# WITHOUT a console window - so double-clicking opens the app directly, with no
# black terminal behind it. Kept at the project root so it can find the package.
from vulnscope.gui import main

if __name__ == "__main__":
    main()
