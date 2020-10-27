#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
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
    char* permissions = (char*)malloc(11);
    permissions[0] = S_ISDIR(fileStat.st_mode) ? 'd' : '-';
    permissions[1] = fileStat.st_mode & S_IRUSR ? 'r' : '-';
    permissions[2] = fileStat.st_mode & S_IWUSR ? 'w' : '-';
    permissions[3] = fileStat.st_mode & S_IXUSR ? 'x' : '-';
    permissions[4] = fileStat.st_mode & S_IRGRP ? 'r' : '-';
    permissions[5] = fileStat.st_mode & S_IWGRP ? 'w' : '-';
    permissions[6] = fileStat.st_mode & S_IXGRP ? 'x' : '-';
    permissions[7] = fileStat.st_mode & S_IROTH ? 'r' : '-';
    permissions[8] = fileStat.st_mode & S_IWOTH ? 'w' : '-';
    permissions[9] = fileStat.st_mode & S_IXOTH ? 'x' : '-';
    permissions[10]='\0';

    return permissions;
}

char** parse_text(char *text)
{
    char *token;
    char **parameters = (char**)malloc(2*sizeof(char*));
    charIndex = 0;

    token=strtok(text, ": \n");
    while( token != NULL)
    {
        parameters[charIndex] = (char*)malloc(strlen(token));
        strcpy(parameters[charIndex],token);
        charIndex++;
        token = strtok(NULL, ": ");
    }
    
    if(charIndex==2){
        char *pos;
        if ((pos=strchr(parameters[1], '\n')) != NULL)
        {
            *pos = '\0';
        }
    }

    return parameters;
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
                int prevLength = strlen(answer);
                char *lastAccessed = ctime(&stats.st_atime);
                char *lastModified = ctime(&stats.st_mtime);
                // Get the size of file.
                char size[10];
                sprintf(size,"%ld",stats.st_size);
                size[strlen(size)] = '\0';

                // Get the permissions of the file.
                char *permissions = get_permissions(stats);

                answer = realloc(answer,
                        strlen(answer)+strlen(dirEntry->d_name)+strlen(path)+strlen(lastAccessed)
                        +strlen(lastModified) + strlen(size) + strlen(permissions) + 5);

                sprintf(answer+prevLength,"%s%s\n%s\n%s\n%s%s\n",
                        path,dirEntry->d_name,size,permissions,lastAccessed,lastModified);
                answer[strlen(answer)] = '\0';

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

    answer = realloc(answer,
                        strlen(name)+strlen(size)+strlen(uid)+strlen(gid)+strlen(links)+strlen(permissions)
                        +strlen(lastAccessed) + strlen(lastModified) + strlen(lastChanged) + 5);
    sprintf(answer,"%s%s%s%s%s%s%s%s%s",name,permissions,size,uid,gid,links,lastAccessed,lastModified,lastChanged);
}

void set_answer(char *text)
{
    int length = strlen(text);
    answer = realloc(answer,length + 1);
    sprintf(answer,"%s",text);
}

int check_password(char *actual_password)
{
    char candidate[20];
    printf("\nEnter the password: ");

    scanf("%[^\n]s",candidate);

    if(strcmp(candidate,actual_password) == 0)
    {
        return 1;
    }else return 0;
}

void new_register(char *username)
{
    char password[20];
    printf("\nPlease enter your passowrd: ");
    scanf(" %s",password);
    
    FILE *registerFile = fopen("users.txt","a");
    fprintf(registerFile,"%s : %s\n",username,password);

    int length = strlen("Account created successfully : ");
    answer = realloc(answer,length + strlen(username) + 2);
    sprintf(answer,"Account created successfully : %s\n",username);
}

void login(char *username)
{
    FILE *loginFile = fopen("users.txt","r");
    char line[200];

    int existent_user = 0;

    while(fgets(line,200,loginFile) != NULL )
    {
        char **parameters = (char**)malloc(2*sizeof(char*));
        parameters = parse_text(line);
        if(strcmp(parameters[0],username)==0)
        {
            if(check_password(parameters[1]))
            {
                int length = strlen("Successfully logged in : ");
                answer = realloc(answer,length + strlen(parameters[0]) + 2);
                sprintf(answer,"Succesfully logged in : %s\n",parameters[0]);
            }else{
                set_answer("Incorrect password!\n");
            }

            existent_user = 1;
        }
    }
    if(!existent_user)
    {
        printf("User not existent, want to register? [Y/N] ");
        char res;
        scanf("%c",&res);
        if(res == 'N')
        {
            set_answer("OK\n");
        }else{
            printf("\nEnter your name, please: ");
            char new_name[20];
            scanf(" %s",new_name);
            new_register(new_name);
        }
        
    }
}



void sonLobby(char *command)
{
    pid_t pidNephew;
    int socketP[2]; 

    // restart the answer.
    answer = (char*)malloc(sizeof(char*));

    // Parse the command.
    char **parameters = parse_text(command);
    // Two words were not sent.
    if(charIndex!=2)
    {
        if(!(strcmp(parameters[0],"login") && strcmp(parameters[0],"myfind") &&
            strcmp(parameters[0],"mystat")))
        {
            write_fifo("Missing Parameter.\n",20);
        }else{
            if(!strcmp(parameters[0],"quit"))
            {
                write_fifo("QUIT",5);
            }else{
                write_fifo("Invalid command.\n",18);
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
        if(write(socketP[1], parameters[0], strlen(parameters[0])) <0)
        {
            perror("ERROR AT WRITING COMMAND IN SON");
        }

        // Wait for response from the nephew.
        int response;
        while(read(socketP[1],&response,sizeof(int)) <= 0);

        if(write(socketP[1], parameters[1], strlen(parameters[1])) <0)
        {
            perror("ERROR AT WRITING PARAMETER IN SON");
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
        char newCommand[255];
        char parameter[255];

        int nread;

        if((nread = read(socketP[0],newCommand,255)) < 0)
        {
            perror("ERROR AT READING COMMAND IN NEPHEW");
        }
        newCommand[nread] = '\0';

        // Send a response to the son that the nephew read the command.
        int response = 1;
        write(socketP[0],&response,sizeof(int));

        if((nread = read(socketP[0],parameter,254)) < 0)
        {
            perror("ERROR AT READING PARAMETER IN NEPHEW");
        }
        parameter[nread] = '\0';

        int valid = 0;

        // See what function to call.
        if(strcmp(newCommand,"myfind") == 0)
        {
            findFiles("..",parameter,"/");
            valid=1;
        }
        if(strcmp(newCommand,"mystat") == 0)
        {
            statFile(parameter);
            valid=1;
        }
        if(strcmp(newCommand,"login") == 0)
        {
            login(parameter);
            valid=1;
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

    int pipeSon[2];
    // findFiles(getenv("HOME"),wantedFile,"/");

    // printf("%s",answer);
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
            if(write(pipeSon[1],command,strlen(command)) <0 )
            {
                perror("ERROR AT WRITING IN PIPE TO SON");
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

            printf("%s\n",finalAnswer);
            printf("------------\n");

            close(fdFifo);
            wait(NULL);
            
        }else{
            close(pipeSon[1]);
            char newCommand[255];

            // Read from the parent through the pipe.
            int nread;
            if((nread =read(pipeSon[0],newCommand,255)) < 0)
            {
                perror("ERROR AT READING FROM PIPE FROM FATHER");
            }
            newCommand[nread] = '\0';

            close(pipeSon[0]);
            sonLobby(newCommand);
        }   
    }
}