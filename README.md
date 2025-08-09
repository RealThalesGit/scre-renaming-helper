# Tool made with ChatGPT, functions name can be strange so dont worry ;3

I made this tool for renaming all the stripped functions (you need v36) and you dont have to rename everything

Requirements, IDA Pro 9.0, Diaphora for generating the sqlite that you will need

So firstly, generate the v36 sqlite (can be arm64 or armeabi-v7a) but make sure if the other versions (v13 for example) have architecture for them, if it does have, good, generate them, it will take a time, for me it took 2 hours, after you generated the sqlites, open the file "renaming-helper.py"  on ida pro, by going to "File > Script File" then you got into the script! now, select the stripped lib and symbols lib, then click on "Run Matching" it will take a while like diaphora, but when it generates, click in "Apply Rename in base DB" it will rename all the funtions! Boom! You renamed them all in a second!
