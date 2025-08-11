# Tool made with ChatGPT, function names can be strange so don't worry ;3
I made this tool for renaming all stripped functions (you need v36), but you don’t have to rename everything manually.

# First, generate the v36 JSON

# Secondly, Open the file called "renaming-helper.py" on IDA Pro 9.0 (tested on), press Alt+F7 or just go to File > Script File
# Now I recommend you setting Threshold low, because it gets more name functions, but do everything you want, now load the target json, (v36.218 from brawl stars, for example), the target json should have debug symbols, which is very useful for us, then click on the "Run Match" button to start, you can cancel it too, once you done, click on the "Apply Renaming" button, it may take a while to rename everything, once you finish it, you renamed all functions in a second!

You can test with other sc games, if they have symbols!
