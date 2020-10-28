#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *answer; //Used for storing all the found files.
char fifoFile[] = "fifoFile";

int charIndex;

int check_name(char *text, char *pattern)
{
    if(strstr(text,pattern) != NULL)
    {
        return 1;
    }
    return 0;
}

char* get_permissions(struct stat fileStat)
{
    char letters[4]="rwx";
    int flags[]={0, S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP,
                S_IROTH, S_IWOTH, S_IXOTH};
    char* permissions = (char*)malloc(11);
    permissions[0] = S_ISDIR(fileStat.st_mode) ? 'd' : '-';

    for(int i=1;i<10;i++)
    {
        permissions[i] = fileStat.st_mode & flags[i] ? letters[(i-1)%3] : '-';

    }
    permissions[10]='\0';

    return permissions;
}

char** parse_text(char *text)
{
    char *token;
    char **parameters = (char**)malloc(4*sizeof(char*));
    charIndex = 0;

    token=strtok(text, ": \n");
    while( token != NULL)
    {
        parameters[charIndex] = (char*)malloc(strlen(token));
        strcpy(parameters[charIndex],token);
        charIndex++;
        token = strtok(NULL, ": ");
    }
    
    char *pos;
    if ((pos=strchr(parameters[charIndex-1], '\n')) != NULL)
    {
        *pos = '\0';
    }
    

    return parameters;
}

char* check_existent_user(char *user)
{
    FILE *loginFile = fopen("users.txt","r");
    char line[200];

    while(fgets(line,200,loginFile) != NULL )
    {
        char **parameters = (char**)malloc(2*sizeof(char*));
        parameters = parse_text(line);
        if(strcmp(parameters[0],user)==0)
        {
            return parameters[1];
        }
    }

    return NULL;
}

void write_fifo(char *newAnswer, int answer_length)
{
    //Now, write in the fifo which leads to the father.
    int fdFifo;
    if((fdFifo = open(fifoFile, O_WRONLY)) < 0)
    {
        perror("ERROR AT OPENING FIFO WRITE END");
    }

    write(fdFifo,&answer_length,sizeof(int));
    
    write(fdFifo,newAnswer,answer_length);

    close(fdFifo);
}

void set_answer(char *text)
{
    int length = strlen(text);
    int current_length = strlen(answer);
    answer = realloc(answer,current_length + length + 1);
    sprintf(answer+current_length,"%s",text);
}

void findFiles(char* directory, char *fileName,char *path)
{
    DIR *current_directory;
    struct dirent *dirEntry; // This will hold information about files/directories.
    struct stat stats; //This will hold more information about files.

    //Open the current directory.
    if((current_directory = opendir(directory)) == NULL)
    {
        perror("Cannot open directory");
        
        return;
    }
    chdir(directory);
    //As long as we are in a valid directory, continue.
    while( (dirEntry = readdir(current_directory)) != NULL)
    {
        //Get the stats of the current file/directory in order to determine if it is a file or directory.
        lstat(dirEntry -> d_name, &stats);
        if(S_ISDIR(stats.st_mode))
        {
            //If it is a directory, check it is '.' or '..', if so, ignore.
            if(strcmp(".",dirEntry->d_name) == 0 || strcmp("..",dirEntry->d_name)==0)
            {
                continue;
            }else{
                //Otherwise, continue the search from that directory.
                
                char tempPath[1000];
                sprintf(tempPath,"%s",path);
                sprintf(tempPath+strlen(tempPath),"%s/",dirEntry->d_name);
                tempPath[strlen(tempPath)]='\0';

                findFiles(dirEntry->d_name,fileName,tempPath);
            }
        }else{
            if(check_name(dirEntry->d_name,fileName))
            {
                // Reallocate memory for 'answer' so the new file, its last acces time, last modification time and size
                // be written
                char *lastAccessed = ctime(&stats.st_atime);
                char *lastModified = ctime(&stats.st_mtime);
                // Get the size of file.
                char size[10];
                sprintf(size,"%ld\n",stats.st_size);
                size[strlen(size)] = '\0';

                // Get the permissions of the file.
                char *permissions = get_permissions(stats);

                set_answer(path);
                set_answer(dirEntry->d_name);
                set_answer("\n");
                set_answer(size);
                set_answer(permissions);
                set_answer("\n");
                set_answer(lastAccessed);
                set_answer(lastModified);
                set_answer("\n");
            }
        }
    }
    //Go to the previous directory, and close the current one.
    chdir("..");
    closedir(current_directory);
}

void statFile(char *fileName)
{
    struct stat stats;
    lstat(fileName, &stats);

    char name[50];
    sprintf(name,"File name: %s \n",fileName);

    // Get the permissions of the file.
    char permissions[25];
    sprintf(permissions,"Permissions: %s\n",get_permissions(stats));

    // Get the size of the file.
    char size[20];
    sprintf(size,"Size: %ld\n",stats.st_size);
    size[strlen(size)] = '\0';
    
    // Get the User ID and Group ID
    char uid[20],gid[20];
    sprintf(uid,"User ID: %d\n",stats.st_uid);
    uid[strlen(uid)] = '\0';
    sprintf(gid,"Groupd ID: %d\n",stats.st_gid);
    gid[strlen(gid)]='\0';

    // Get the number of links.
    char links[20];
    sprintf(links,"Links: %ld\n",stats.st_nlink);

    // Get the the last accessed, modified and changed time.
    char lastAccessed[50],lastModified[50],lastChanged[50];
    sprintf(lastAccessed,"Last time accessed: %s",ctime(&stats.st_atime));
    sprintf(lastModified,"Last time modified: %s",ctime(&stats.st_mtime));
    sprintf(lastChanged,"Last time changed: %s",ctime(&stats.st_ctime));

    set_answer(name);
    set_answer(size);
    set_answer(uid);
    set_answer(gid);
    set_answer(links);
    set_answer(permissions);
    set_answer(lastAccessed);
    set_answer(lastModified);
    set_answer(lastChanged);
}

int check_password(char *actual_password, char *candidate)
{
    if(strcmp(candidate,actual_password) == 0)
    {
        return 1;
    }else return 0;
}

void new_register(char *username,char *password)
{   
    char *verify = check_existent_user(username);
    if(verify != NULL)
    {
        set_answer("User already registered.\n");
        return;
    }

    FILE *registerFile = fopen("users.txt","a");
    fprintf(registerFile,"%s : %s\n",username,password);

    set_answer("Account created successfully : ");
    set_answer(username);
}

void login(char *username, char *password)
{
    char *actual_password = check_existent_user(username);

    if(actual_password == NULL)
    {
        set_answer("User not registered.\n");
        return ;
    }

    if(check_password(password, actual_password))
    {
        set_answer("Successfully logged in: ");
        set_answer(username);
    }else{
        set_answer("Incorrect password!\n");
    }
}

void sonLobby(char *command, int notLogged)
{
    pid_t pidNephew;
    int socketP[2]; 

    // restart the answer.
    answer = (char*)malloc(sizeof(char*));

    // Parse the command.
    char **parameters = parse_text(command);
    // Take in consideration special cases.
    if(charIndex<2)
    {
        if(!(strcmp(parameters[0],"login") && strcmp(parameters[0],"myfind") &&
            strcmp(parameters[0],"mystat") && strcmp(parameters[0],"register")))
        {
            write_fifo("Missing Parameter.\n",20);
        }else{
            if(!strcmp(parameters[0],"quit"))
            {
                write_fifo("QUIT",5);
            }else{
                if(!strcmp(parameters[0],"clear"))
                {
                    write_fifo("CLEAR",6);
                }else{
                    write_fifo("Invalid command.\n",18);
                }
            }
        }
        exit(0);
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socketP) < 0) 
    { 
        perror("Error at socketpair"); 
        exit(1); 
    }

    if((pidNephew = fork()) == -1)
    {
        perror("ERROR AT FORK IN SON");
    }

    if(pidNephew) // Parent
    {
        close(socketP[0]);
        for(int i=0;i<charIndex;i++)
        {
            int length = strlen(parameters[i]);
            if(write(socketP[1], &length, sizeof(int)) <0)
            {
                perror("ERROR AT WRITING COMMAND IN SON");
            }
            if(write(socketP[1], parameters[i], length) <0)
            {
                perror("ERROR AT WRITING COMMAND IN SON");
            }
        }

        wait(NULL);
        char *newAnswer;
        int answer_length;
        read(socketP[1],&answer_length,sizeof(int));
        newAnswer = (char*)malloc(answer_length);
        
        read(socketP[1],newAnswer,answer_length);
        close(socketP[1]);

        if(strlen(newAnswer) > 0)
            write_fifo(newAnswer, answer_length);
        else write_fifo("No file found.\n",16);

        exit(0);
    }else{  // Child
        close(socketP[1]);

        char **words;
        words = (char**)malloc(charIndex*(sizeof(char*)));
        for(int i=0;i<charIndex;i++)
        {
            int length;
            if(read(socketP[0], &length, sizeof(int)) <0)
            {
                perror("ERROR AT WRITING COMMAND IN SON");
            }
            words[i] = (char*)malloc(length);
            if(read(socketP[0], words[i], length) <0)
            {
                perror("ERROR AT WRITING COMMAND IN SON");
            }
            words[i][length]='\0';
        }

        int valid = 0;
        if(notLogged & !strcmp(words[0], "login"))
        {

        }
        // See what function to call.
        if(strcmp(words[0],"myfind") == 0) 
        {
            if(charIndex==2){
                if(!notLogged){
                    findFiles("..",words[1],"/");
                }else{
                    set_answer("You have to be logged in!");
                }
                valid=1;
        }
        }
        if(strcmp(words[0],"mystat") == 0)
        {
            if(charIndex==2){
                if(!notLogged){
                    statFile(words[1]);
                }else{
                    set_answer("You have to be logged in!");
                }
                valid=1;
            }
        }
        if(strcmp(words[0],"login") == 0)
        {
            if(charIndex==3){
                if(notLogged){
                    login(words[1],words[2]);
                }else{
                    set_answer("Already logged in!");
                }
                valid=1;
            }
        }
        if(strcmp(words[0],"register") == 0)
        {
            if(charIndex==3){
                new_register(words[1],words[2]);
                valid=1;
            }
        }

        if(valid)
        {
            int answer_length = strlen(answer);
            write(socketP[0],&answer_length,sizeof(int));
            write(socketP[0],answer,answer_length);
        }else{
            int answer_length=18;
            char notValid[18] = "Invalid command.\n";
            write(socketP[0],&answer_length,sizeof(int));
            write(socketP[0],notValid,18);
        }

        close(socketP[0]);
        exit(0);
    }
}

int main()
{
    pid_t sonPid;
    char command[255];

    int notLogged =1; // Check if the user is logged in.
    int pipeSon[2];
    
    /*I will use 3 ways for communication:
    1. Pipe to send data to the first child.
    2. Fifo to send data from the first child to father.
    3. SocketPair to send data between first child and grandchild.
    */

    // Run until it receives "quit".
    while(fgets(command,255,stdin))
    {
        // scanf("%[^\n]s",command);
        if(command[0]=='\n')continue;

        if(pipe(pipeSon)<0)
        {
            perror("ERROR AT PIPE IN THE FAHTER");
        }

        // Remove the existing file to avoid the possibility to overwrite.
        remove(fifoFile);
        if(mknod(fifoFile, S_IFIFO | 0666, 0) <0 )
        {
            perror("ERROR AT CREATING FIFO.");
        }

        // Create the child.
        if ((sonPid = fork()) < 0)
        {
            perror("ERROR AT FORK IN THE FATHER");
            exit(0);
        }

        if(sonPid) // Parent.
        {
            // Write to the son through the pipe //
            // ---------------------------- //
            close(pipeSon[0]);
            int command_length = strlen(command);
            if(write(pipeSon[1],&command_length,sizeof(int)) <0 )
            {
                perror("ERROR AT WRITING IN PIPE TO SON (length of command)");
            }
            if(write(pipeSon[1],command,strlen(command)) <0 )
            {
                perror("ERROR AT WRITING IN PIPE TO SON");
            }
            if(write(pipeSon[1],&notLogged,sizeof(int)) <0 )
            {
                perror("ERROR AT WRITING IN PIPE TO SON (the login variable)");
            }
            close(pipeSon[1]);
            // ---------------------------- //

            // Read from the son through the FIFO. //
            // ---------------------------- //
            char *finalAnswer;
            int answer_length;
            
            int fdFifo;
            if((fdFifo = open(fifoFile,O_RDONLY )) < 0)
            {
                perror("ERROR AT READING FROM FIFO ");
            }
            
            read(fdFifo, &answer_length,sizeof(int));

            finalAnswer = (char*)malloc(answer_length);

            read(fdFifo, finalAnswer, answer_length+1);
            finalAnswer[answer_length]='\0';
            // ---------------------------- //

            // If the command is "quit", exit the program. All the children will be already
            // finished by this time.
            if(!strcmp(finalAnswer,"QUIT"))
            {
                printf("Exit...");
                exit(0);
            }

            if(!strcmp(finalAnswer,"CLEAR"))
            {
                // Clears the screen.
                printf("\e[1;1H\e[2J");
            }else{
                if(strstr(finalAnswer,"Successfully"))notLogged=0;
                printf("%s\n",finalAnswer);
                printf("------------\n");

                close(fdFifo);
                wait(NULL);
            }
            
        }else{
            close(pipeSon[1]);
            char newCommand[255];

            // Read from the parent through the pipe.
            int nread;
            int notLogged;
            int length;

            if((read(pipeSon[0],&length,sizeof(int))) < 0)
            {
                perror("ERROR AT READING FROM PIPE FROM FATHER");
            }

            if((nread = read(pipeSon[0],newCommand,length)) < 0)
            {
                perror("ERROR AT READING FROM PIPE FROM FATHER");
            }
            newCommand[nread] = '\0';

            if((read(pipeSon[0],&notLogged,sizeof(int))) < 0)
            {
                perror("ERROR AT READING FROM PIPE FROM FATHER");
            }

            close(pipeSon[0]);
            sonLobby(newCommand,notLogged);
        }   
    }
}