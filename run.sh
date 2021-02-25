make clean
make 
sudo make install
cd ../testing
yara simpleSearch.yara exampleFile.txt
