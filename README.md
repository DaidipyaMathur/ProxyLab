# ProxyLab

sudo apt-get install -y build-essential cmake libboost-all-dev libssl-dev

mkdir build

cd build

cmake ..

make

./proxylab

gzip:

sudo apt-get install -y zlib1g-dev

SQLCipher:

sudo apt-get install -y libsqlcipher-dev

PACKAGES:

sudo apt-get install -y pkg-config

CHANGE set(ENV{PKG_CONFIG_PATH} "/usr/lib/x86_64-linux-gnu/pkgconfig") in cMakeLists.txt to set(ENV{PKG_CONFIG_PATH} "path"), where path can be found by sudo find / -name "sqlcipher.pc". You'll get output of the form path/sqlcipher.pc 

HOW TO USE SQLCIPHER: 

sudo apt-get install -y sqlcipher (only once)

sqlcipher history.db

PRAGMA key ='proxylab';

ADD ROOTCA FILES TO BUILD AFTER MAKING BUILD

NOW USE LIKE NORMAL SQL



