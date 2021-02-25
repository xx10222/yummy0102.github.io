#define _CRT_SECURE_NO_WARNINGS
#include<pthread.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<sys/sem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXLINE 1024  //hihi~ welcome~
#define PORTNUM 3600
#define IP "192.168.1.88" //centos server ip(change)

#define HTTP_URL "http://192.168.1.88:8000/" //http directory server ip + port number for http client(change)
#define WEBSOCKET_URL "ws://192.168.1.88:5000" //websocket server ip + port number for websocket client(change)

#define srv_localpath "/home/kwudev/test/" //server local path (location of file) (change)


struct Info1{
   char ver[10]; //request version
   int size;
};

struct Info2{
   char filePath[50];
   char sendType[20];
   char os[20];
   int port;
   char hostname[256];
};

struct sftp_Info{

   char username[MAXLINE];
   char password[MAXLINE];
};

// init mutex
pthread_mutex_t mutex_lock;

// share data
int visitor = 0;

void *thread_function(void *data)
{
        int sockfd = *((int *) data);
        int readn;

        socklen_t addrlen;

        char buf[MAXLINE];
	char cli_cmd[MAXLINE]; //client exe command
	char time_str[20]; //client connect time
	char cli_ip[20]; //client ip
	char fileName[20]; //file name which send to client

	char log[MAXLINE];
	char update_log[MAXLINE];
	char update_cmd[MAXLINE];

	FILE *fp;
	FILE *up_fp;
	
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	printf("now: %d-%d-%d.%d:%d:%d\n", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour,  tm.tm_min, tm.tm_sec);

	sprintf(time_str, "%d-%d-%d.%d:%d:%d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour,  tm.tm_min, tm.tm_sec);

	struct sockaddr_in client_addr;

        memset(buf, 0x00, MAXLINE);
        addrlen = sizeof(client_addr);
        getpeername(sockfd, (struct sockaddr *) &client_addr, &addrlen);
   
   	struct Info1 cli_info1;
  	struct Info2 cli_info2;
  	struct sftp_Info sftp_info; //sftp struct
	
  	memset(&cli_info1, 0, sizeof(struct Info1)); //initilaize struct
  	memset(&cli_info2, 0, sizeof(struct Info2));
  	memset(&sftp_info, 0, sizeof(struct sftp_Info));  
	
  	int receivedBytes;
   
  	//receive first struct
  	receivedBytes = recv(sockfd, (struct Info1*)&cli_info1, sizeof(cli_info1), 0);
  	if(receivedBytes <= 0)
  	   write(sockfd, "nothing_1", strlen("nothing_1"));
	
  	printf("Client IP : [%s]\n", inet_ntoa(client_addr.sin_addr));      //save at log.txt(client ip)
  	strcpy(cli_ip, inet_ntoa(client_addr.sin_addr)); 	//save client ip

  	printf("\nversion : %s\nsize: %d\n\n",cli_info1.ver, cli_info1.size); //test
  	 
  	//receive second struct
  	receivedBytes = recv(sockfd, (struct Info2*)&cli_info2, sizeof(cli_info2), 0);
  	if(receivedBytes <= 0)
  	   write(sockfd, "nothing_2", strlen("nothing_2"));
	
  	printf("\nfile path : %s\nprotocol : %s\nos : %s\nip : %s\nport : %d\nhostname : %s\n\n",cli_info2.filePath, cli_info2.sendType, cli_info2.os, cli_ip, cli_info2.port, cli_info2.hostname);
	
	//client wants new version!!
	if(!strncmp(cli_info1.ver,"new",3)) //window, ubuntu, centos
	{
		char new_ver[3][10]={0,};
		char line[255];
		int index = 0;

		FILE* file = fopen("new.txt", "r"); //lastest version list file
		if (file == NULL) {
			printf("failed to open 'new.txt'\n");
			return -1;
		}
		
		while (fgets(line, sizeof(line), file) != NULL ) {
			line[strlen(line)-1]='\0';
			strcpy(new_ver[index],line);
			index++;
			
		}
		fclose(file);

		if(!strncmp(cli_info2.os,"Windows",7))
		{
			strcpy(cli_info1.ver, new_ver[0]);
		}
		else if(!strncmp(cli_info2.os,"Ubuntu",6))
		{
			strcpy(cli_info1.ver, new_ver[1]);
		}
		else if(!strncmp(cli_info2.os,"CentOS",6))
		{
			strcpy(cli_info1.ver, new_ver[2]);
		}
	}

	sprintf(log, "%s %s %s %d %s %s %s\n", time_str, cli_info2.hostname, cli_ip, cli_info2.port, cli_info2.os, cli_info2.sendType, cli_info1.ver);
	printf("log : %s", log);

	sprintf(update_log, "%s %s %d %s %s %s\n", cli_info2.hostname, cli_ip, cli_info2.port, cli_info2.os, cli_info2.sendType, cli_info1.ver);

	//receive add information(struct) for send file
	if(!strncmp(cli_info2.sendType,"https",5)) //https
	{
		printf("no need more information for https!\n");
	}
	else if(!strncmp(cli_info2.sendType,"sftp",4)) //SFTP
	{
		//receive sftp struct
		receivedBytes = recv(sockfd, (struct sftp_Info*)&sftp_info, sizeof(sftp_info), 0);
		if(receivedBytes <= 0)
      			write(sockfd, "nothing_3", strlen("nothing_3"));
		
	}
	else if(!strncmp(cli_info2.sendType,"websocket",9)) //Websocket
	{
		printf("no need more information for websocket!\n");
	}

	strcpy(fileName, cli_info1.ver); //file name to send
	if(!strncmp(cli_info2.os,"Windows",7))
	{
		strcat(fileName, ".zip");
	}
	else if(!strncmp(cli_info2.os,"Ubuntu",6))
	{
		strcat(fileName, ".tar.gz");
	}
	else if(!strncmp(cli_info2.os,"CentOS",6))
	{
		strcat(fileName, ".tar.gz");
	}
	//is there version file which client wants?
	char srv_path[100]; //file place
	strcpy(srv_path, srv_localpath);
	strcat(srv_path,cli_info2.os); //file directory of os
	strcat(srv_path,"/");
	strcat(srv_path,fileName);

	if(access(srv_path,F_OK) < 0) //if no file? thread exit
	{
		printf("no file\n");
		write(sockfd, "no file", strlen("no file")); //send msg to client
		close(sockfd);
		printf("Client thread end\n");

        	// critical section
        	pthread_mutex_lock(&mutex_lock);
       		visitor--;
        	pthread_mutex_unlock(&mutex_lock);
        	// end

        	return 0;
	}

	FILE *fp2;
	fp2 = fopen("update.txt","r");

	char *log_ver = {0,}; //most recent downloaded version _ client
	int i;
	if(fp2 != NULL)
	{
		char buffer[1024];
		memset(buffer,0,sizeof(buffer));
		while(!feof(fp2))
		{
			fgets(buffer,sizeof(buffer),fp2);
			buffer[strlen(buffer) - 1] = '\0';
			strtok(buffer, " ");
			char *ptr = strtok(NULL, " ");
			if(ptr==NULL)
				break;
			if(!strcmp(ptr, cli_ip))
			{
				for(i=0; i<3; i++)
				{
					strtok(NULL, " ");
				}
				ptr = strtok(NULL, " ");
				log_ver = ptr;
				break;
			}
			memset(buffer, 0, sizeof(buffer));
		}
		fclose(fp2);
	}
printf("!!!!!!!!!!!!!!!!!!!%s %s\n",cli_info1.ver,log_ver);
	if(log_ver != NULL)
	{
		if(!strcmp(cli_info1.ver,log_ver))
		{
			strcpy(cli_cmd, "error! : already use this ver!\nDo you want to continue? (Y/N)\n");
			write(sockfd, cli_cmd, strlen(cli_cmd)); //send msg to client

			char ch[10];
			memset(ch, 0x00, 10);
			read(sockfd,ch,10);
			printf("ch : %s\n",ch);
			if(!strncmp(ch,"N",1)||!strncmp(ch,"n",1))
			{
				close(sockfd);
				printf("Client thread end\n");
	
	        		// critical section
	        		pthread_mutex_lock(&mutex_lock);
	        		//visitor--;
	        		pthread_mutex_unlock(&mutex_lock); 
				return 0;
			}
		}
	}
        printf("server has the file that the client wants!\n");
	printf("wait...\n"); 

	if(!strncmp(cli_info2.sendType,"https",5)) //HTTPS -> http_server is running anytime:8000
	{
		printf("send type : https\n"); 
		char url[MAXLINE]="";
		strcpy(url, HTTP_URL);

		if(!strcmp(cli_info2.os,"Windows"))
		{
			strcat(url, "Windows/");	
			strcpy(cli_cmd,"http_cli.exe ");
			//strcpy(cli_cmd, "python http_cli.py ");
		}
		else if(!strcmp(cli_info2.os,"Ubuntu"))
		{
			strcat(url, "Ubuntu/");
			strcpy(cli_cmd,"./http_cli ");
			//strcpy(cli_cmd, "python3 http_cli.py ");
		}
		else if(!strcmp(cli_info2.os,"CentOS"))
		{
			strcat(url, "CentOS/");
			strcpy(cli_cmd,"./http_cli ");
			//strcpy(cli_cmd, "python3 http_cli.py ");
		}
		//strcpy(cli_cmd, "python3 http_cli.py ");
		strcat(url, fileName);
		strcat(cli_cmd, url);
		strcat(cli_cmd," ");
		strcat(cli_cmd, fileName);
		strcat(cli_cmd," ");
		strcat(cli_cmd,"\"");
		strcat(cli_cmd,cli_info2.filePath);
		strcat(cli_cmd,"\"");

		printf("cli cmd : %s\n",cli_cmd);
	
   		write(sockfd, cli_cmd, strlen(cli_cmd)); //send msg to client
		printf("\nwait for cli...\n");
		memset(buf, 0x00, MAXLINE);
		read(sockfd,buf,MAXLINE);
		printf("\n\n");
		printf("msg : %s\n",buf);
	}

	else if(!strncmp(cli_info2.sendType,"sftp",4)) //SFTP_revise : localpath
	{ 	//<IP> <username> <password> <localpath> <filepath>
		//./sftp_srv cli_ip sftp_info.username sftp_info.password /home/kwudev/real_test/OS/temp.txt /home/jiwon/path
		printf("send type : sftp\n"); 
		char localpath[MAXLINE];
		strcpy(localpath,srv_localpath);

		if(!strcmp(cli_info2.os,"Windows"))
		{
			strcat(localpath, "Windows/");	
			strcpy(cli_cmd,"sftp_srv.exe ");
			//strcpy(cli_cmd, "sftp_srv.py ");
		}
		else if(!strcmp(cli_info2.os,"Ubuntu"))
		{
			strcat(localpath, "Ubuntu/");	
			strcpy(cli_cmd,"./sftp_srv ");
		}
		else if(!strcmp(cli_info2.os,"CentOS"))
		{
			strcat(localpath, "CentOS/");	
			strcpy(cli_cmd,"./sftp_srv ");
		}
		//strcpy(cli_cmd, "python3 sftp_srv.py ");
		strcat(localpath, fileName); //change sprintf..?
		strcat(cli_cmd, cli_ip);
		strcat(cli_cmd, " ");
		strcat(cli_cmd, sftp_info.username);
		strcat(cli_cmd, " ");
		strcat(cli_cmd, sftp_info.password);
		strcat(cli_cmd, " ");
		strcat(cli_cmd, localpath);
		strcat(cli_cmd, " ");
		strcat(cli_cmd,"\"");
		strcat(cli_cmd, cli_info2.filePath);
		strcat(cli_cmd,"\"");
		printf("cli cmd : %s\n",cli_cmd); 
	printf("password : %s\n",sftp_info.password);
   		write(sockfd, cli_cmd, strlen(cli_cmd)); //send msg to client
		printf("\nwait for cli...\n");
		memset(buf, 0x00, MAXLINE);
		read(sockfd,buf,MAXLINE);
		printf("\n\n");
		printf("msg : %s\n",buf);
	}

	else if(!strncmp(cli_info2.sendType,"websocket",9)) //Websocket -> websocket server is running anytime(9998)
	{ //./python3 websocket_cli.py cli_info2.os filename - python3 websocket_cli.py Ubuntu b.jpg
		printf("send type : websocket\n"); 

		if(!strcmp(cli_info2.os,"Windows"))
		{	
			strcpy(cli_cmd,"websocket_cli.exe ");
			//strcpy(cli_cmd, "python websocket_cli.py "); //temporary command
		}
		else
		{
			strcpy(cli_cmd,"./websocket_cli ");
			//strcpy(cli_cmd, "python3 websocket_cli.py "); //temporary command
		}
		//strcpy(cli_cmd, "python3 websocket_cli.py "); //temporary command
		strcat(cli_cmd, cli_info2.os);
		strcat(cli_cmd," ");
		strcat(cli_cmd, fileName);
		strcat(cli_cmd, " ");
		strcat(cli_cmd,"\"");
		strcat(cli_cmd,cli_info2.filePath);
		strcat(cli_cmd,"\"\"");
		strcat(cli_cmd," ");
		strcat(cli_cmd, WEBSOCKET_URL);
		printf("cli cmd : %s\n",cli_cmd); 

   		write(sockfd, cli_cmd, strlen(cli_cmd)); //send msg to client
		printf("\nwait for cli...\n");
		memset(buf, 0x00, MAXLINE);
		read(sockfd,buf,MAXLINE);
		printf("\n\n");
		printf("msg : %s\n",buf);

	}

	//logfile.txt - [time] [hostname] [ip] [client port] [os] [protocol] [version]
	fp = fopen("logfile.txt", "a");
	if(fp == NULL)
	{
		printf("file open error!\n");
		return 0;
	}
	

	fputs(log, fp); //save log at logfile.txt
	fclose(fp);

	//update.txt - [hostname] [ip] [client port] [os] [protocol] [version] (python)
	//strcpy(update_cmd, "python3.7 update_file.py ");
	strcpy(update_cmd, "./update_file ");
	strcat(update_cmd, update_log);
	system(update_cmd); //execute update_file.py	

        close(sockfd);
        printf("Client thread end\n");

        // critical section
        pthread_mutex_lock(&mutex_lock);
        visitor--;
        pthread_mutex_unlock(&mutex_lock);
        // end

        return 0;
}

int main(int argc, char **argv)
{
        int listen_fd, client_fd;
        socklen_t addrlen;
        int readn;
        char buf[MAXLINE];
        pthread_t thread_id;

        struct sockaddr_in server_addr, client_addr;

        if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   	{
                return 1;
        }

        memset((void *) &server_addr, 0x00, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(IP); //IP revise
        server_addr.sin_port = htons(PORTNUM); //Port number revise

        if(bind(listen_fd, (struct sockaddr *) &server_addr,sizeof(server_addr)) == -1)
   	{
                perror("bind error");
                return 1;
        }

        printf("Main Server Start...\n");

        if(listen(listen_fd, 5) == -1){
                perror("listen error");
                return 1;
        }

        while(1)
  	{
                addrlen = sizeof(client_addr);
                client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen);
                if(client_fd == -1)
                        printf("accept error\n");
                else
      		{
                        pthread_create(&thread_id, NULL, thread_function, (void *) &client_fd);
                        // critical section
                        pthread_mutex_lock(&mutex_lock);
                        printf("Current Client is %d\n", ++visitor);
                        pthread_mutex_unlock(&mutex_lock);
                        // end
                        // Main server will continue even after thread isn't finished
                        pthread_detach(thread_id);
                }
        }
        return 0;
}
