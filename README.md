# AndroVET
<img src='https://github.com/demeter2025/AndroVet/blob/main/Logo.png' />

AndroVET is an android based custom OS vulnerability exploration tool. It is tailored for Android custom OS but it can be used in any other system by replacing the bug diff code database.

AndroVET abstraction layer supports C, C++, Java and Kotlin. The precision layer works with any programming language.

## Necesary dependencies
Before using AndoroVet please make sure you installed:

tqdm:
These can be installed using pip
<pre> ```bash pip install tqdm ``` </pre>
MySql connector:
<pre> ```bash pip install mysql-connector-python ``` </pre>
Multiprocessing:
<pre> ```bash pip install multiprocessing ``` </pre>

AndroVET requires two MySQL databases you will find them in the data folder.
If you are not used to SQL databases, please install lampp 
once it is installed start the Apache and MySql servers:
<pre> ```sudo /opt/lampp/lampp start ``` </pre>
open the web browser and navigate to localhost (127.0.0.1)
select MyPHPAdmin
create a new database called "mydata"
import bugs.sql and common.sql.

the lampp SQL server MUST be ACTIVE to use AndroVET.

To deactivate the SQL server please go to your terminal and write
sudo /opt/lampp/lampp stop


## Notes

Please note, AndroVET was tailored with accuracy in mind and can consume a considerable amount of system resources. We recommend AT LEAST 16 GB of RAM to run the app without any issues. The status bar can fail to update during runtime due to the nature of multiprocessing. If you note this situation, pleasse be patient. AndroVET takes one hour in average to evaluate a complete Android repo, if you run in a laptop or a slower computer the execution time can be as long as 2 hours.

## HOW TO USE AndroVET

usage: file.py [-h] -i INPUT -o OUTPUT [-t THRESHOLD] [-s SKIP]
               [-d DATABASE] [-du DBUSER] [-dp DBPASS] -v VERSION

AndroVET

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input COS root folder
  -o OUTPUT, --output OUTPUT
                        Output folder
  -t THRESHOLD, --threshold THRESHOLD
                        Similarity threshold value
  -s SKIP, --skip SKIP  Skip Precision if you have previouse reports you want
                        ot use
  -d DATABASE, --database DATABASE
                        database name
  -du DBUSER, --dbuser DBUSER
                        database user
  -dp DBPASS, --dbpass DBPASS
                        database password
  -v VERSION, --version VERSION
                        Set up the Android version (and below) filter

The default values are:
database = 'mydata'
dbuser = 'root'
dbpassword = ''
threshold = 85.5
skip = Fasle
Three values (input , output, and version) are REQUIRED. 

## CONTACT US

This is a research open source project, feel free to use it and modify it as needed. If you find any problem executing AndroVET please contact us at researchmail016@gmail.com
We will do our best to answer your questions.

## License

    Copyright [2025] [---------]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
