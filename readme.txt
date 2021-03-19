To run current version of our program:

Install libhyperscan5 from apt repository:

    sudo apt install libhyperscan5

Clone our branch from git:

    git clone https://github.com/BYUTeamYara/yara.git
    git checkout maxChanges

Install and run Yara

    ./bootstrap.sh
    ./configure --enable-hyperscan
    make
    sudo make install
    yara [rule file] [input file]


