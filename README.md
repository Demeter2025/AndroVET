# AndroVET
<img src='https://github.com/demeter2025/AndroVet/blob/main/Logo.png' />

AndroVET is an android based custom OS vulnerability exploration tool. It is tailored for Android custom OS but it can be used in any other system by replacing the bug diff code database.

AndroVET abstraction layer supports C, C++, Java and Kotlin. The precision layer works with any programming language.

## Necesary dependencies
Before using AndoroVet please make sure you installed the following dependencies:

mysql-connector-python
multiprocessing 
tqdm

These can be installed using pip

AndroVET requires a MySQL database containing the provided table 'bugs' (we uploaded a .sql dump file)
If you are not used to SQL databases, please install lampp 
run sudo /opt/lampp start
open the web browser and navigate to localhost (127.0.0.1)
select MyPHPAdmin
create a new database
import the .sql file with the bugs table.

the lampp SQL server MUST be ACTIVE to use AndroVET.

to deactivate the SQL server please go to your terminal and write

sudo /opt/lampp/lampp stop


## Notes

Please note, AndroVET was tailored with accuracy in mind but its abstraction layer can consume a considerable amount of system resources. We recommend AT LEAST 16 GB of RAM to run the app without any issues. The status bar can fail to update during runtime because of the nature of multiprocessing, the app takes close to 30 minutes to evaluate a complete android repo,  but the time can vary according to system resources. Please be patient.

## HOW TO USE AndroVET

to run the app plase clone the repo and go to its main folder.
run the swatch.py by executing python swatch.py [parameters...] 
provide the following parameters:

argv[1] = custom OS folder

argv[2] = datbase name

argv[3] = datbase user

argv[4] = datbase password

argv[5] = save results folder

argv[6] = true/false => print results of the precision layer

argv[7] = set similarity treshold for Layer2 -> recommended value 85.5  


## CONTACT US

This is a research open source project, feel free to use it and modify it as needed. If you find any problem executing AndroVET please contact us at researchmail016@gmail.com
We will do our best to answer your questions.

## License

    Copyright [2022] [Esteban Luques]

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
